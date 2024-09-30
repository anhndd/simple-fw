(* This unikernel is largely inspired by the example at https://github.com/mirage/mirage-nat/ *)

open Lwt.Infix

module Main
    (* our unikernel is functorized over the physical, and ethernet modules
       for the public and private interfaces, so each one shows up as a module
       argument. *)
    (Public_net : Mirage_net.S)
    (Private_net : Mirage_net.S)
    (Public_ethernet : Ethernet.S)
    (Private_ethernet : Ethernet.S)
    (Random : Mirage_crypto_rng_mirage.S)
    (Clock : Mirage_clock.MCLOCK)
    (Time : Mirage_time.S) =
struct
  (* configure logs, so we can use them later *)
  let log = Logs.Src.create "fw" ~doc:"FW device"

  module Log = (val Logs.src_log log : Logs.LOG)

  (* the specific impls we're using show up as arguments to start. *)
  let start public_netif private_netif _public_ethernet _private_ethernet _rng
      () _time =
    (* Creates a set of rules (empty) and a default condition (accept) *)
    let filter_rules = Rules.init false in

    (* Send an arp packet over the public Ethernet interface *)
    let output_ipv4_public dst_mac packet =
      (* Send the custom packet over the Ethernet interface *)
      let len = Cstruct.length packet in
      Public_ethernet.write _public_ethernet dst_mac `IPv4 ~size:len (fun b ->
          Cstruct.blit packet 0 b 0 len;
          len)
      >>= function
      | Ok () ->
          Logs.info (fun m -> m "Ipv4 packet sent successfully");
          Lwt.return_unit
      | Error e ->
          Logs.err (fun m ->
              m "Error sending packet: %a" Public_ethernet.pp_error e);
          Lwt.return_unit
    in

    (* Send an arp packet over the private Ethernet interface *)
    let output_ipv4_private dst_mac packet =
      let len = Cstruct.length packet in
      Private_ethernet.write _private_ethernet dst_mac `IPv4 ~size:len (fun b ->
          Cstruct.blit packet 0 b 0 len;
          len)
      >>= function
      | Ok () ->
          Logs.info (fun m -> m "Ipv4 packet sent successfully");
          Lwt.return_unit
      | Error e ->
          Logs.err (fun m ->
              m "Error sending packet: %a" Private_ethernet.pp_error e);
          Lwt.return_unit
    in

    let vertex_cover = Vertex_cover.init INITIATE in

    (* Periodic function to send a packet *)
    let rec send_packet_periodically output_ipv4 count =
      match vertex_cover.state with
      | INITIATE when count > 0 ->
          let dst_mac = Macaddr.of_string_exn "FF:FF:FF:FF:FF:FF" in
          let packet = Vertex_cover.serialize_message PROB in
          (* Send the packet using the private interface *)
          output_ipv4 dst_mac packet >>= fun () ->
          (* Wait for 5 seconds before sending again *)
          Time.sleep_ns (Duration.of_sec 5) >>= fun () ->
          send_packet_periodically output_ipv4 (count - 1)
      | INITIATE ->
          vertex_cover.state <- COMPUTING;
          Vertex_cover.update_degree vertex_cover vertex_cover.map_unik_neighbor;
          Logs.info (fun m -> m "Moved to state 1 with degree %d" vertex_cover.degree);
          Lwt.return_unit
      | _ -> Lwt.return_unit
    in

    let handle_special_packet :
        Macaddr.t ->
        Cstruct.t ->
        (Macaddr.t -> Cstruct.t -> unit Lwt.t) ->
        Vertex_cover.interface ->
        unit Lwt.t =
     fun src_mac packet output_ipv4 inter ->
      let cmd = Vertex_cover.parse_message packet in
      match cmd with
      | PROB -> (
          let reply_packet = Vertex_cover.serialize_message REPLY in
          match
            Vertex_cover.MacMap.find src_mac vertex_cover.map_unik_neighbor
          with
          | None ->
              let new_neigh : Vertex_cover.unik_neigh = { inter } in
              vertex_cover.map_unik_neighbor <-
                vertex_cover.map_unik_neighbor
                |> Vertex_cover.MacMap.add src_mac new_neigh;
              Logs.debug (fun m ->
                    m "Update Mac address from PROB: %s" (Macaddr.to_string src_mac));
              output_ipv4 src_mac reply_packet
          | Some _ ->
              Logs.debug (fun m ->
                  m "Reveive PROB same Mac address from a unikernel");
              Lwt.return_unit
        )
      | REPLY -> (
          match
            Vertex_cover.MacMap.find src_mac vertex_cover.map_unik_neighbor
          with
          | None ->
              let new_neigh : Vertex_cover.unik_neigh = { inter } in
              vertex_cover.map_unik_neighbor <-
                vertex_cover.map_unik_neighbor
                |> Vertex_cover.MacMap.add src_mac new_neigh;
              Vertex_cover.update_degree vertex_cover vertex_cover.map_unik_neighbor;
              Logs.debug (fun m ->
                m "Update Mac address from REPLY: %s" (Macaddr.to_string src_mac));
              Lwt.return_unit
          | Some _ ->
              Logs.debug (fun m ->
                  m "Reveive REPLY same Mac address from a unikernel");
              Lwt.return_unit
        )
      | _ -> Lwt.return_unit

    in

    (* Forward the (dest, packet) [packet] to the public interface, using [dest] to understand how to route *)
    let output_public : Cstruct.t -> unit Lwt.t =
     fun packet ->
      let len = Cstruct.length packet in
      Public_net.write public_netif ~size:len (fun b ->
          Cstruct.blit packet 0 b 0 len;
          len)
      >|= function
      | Ok () -> ()
      | Error e ->
          Log.warn (fun f -> f "netif write errored %a" Public_net.pp_error e);
          ()
    in

    (* Forward the (dest, packet) [packet] to the private interface, using [dest] to understand how to route *)
    let output_private : Cstruct.t -> unit Lwt.t =
     fun packet ->
      (* For IPv4 only one prefix can be configured so the list is always of length 1 *)
      let len = Cstruct.length packet in
      Private_net.write private_netif ~size:len (fun b ->
          Cstruct.blit packet 0 b 0 len;
          len)
      >|= function
      | Ok () -> ()
      | Error e ->
          Log.warn (fun f -> f "netif write errored %a" Private_net.pp_error e);
          ()
    in

    (* we need to establish listeners for the private and public interfaces *)
    (* we're interested in all traffic to the physical interface; we'd like to
       send ARP traffic to the normal ARP listener and responder,
       handle ipv4 traffic with the functions we've defined above for filtering,
       and ignore all ipv6 traffic. *)
    let listen_public =
      let header_size = Ethernet.Packet.sizeof_ethernet
      and input frame =
        (* Takes an ethernet packet and send it to the relevant callback *)
        match Ethernet.Packet.of_cstruct frame with
        | Ok (header, payload) -> (
            match header.Ethernet.Packet.ethertype with
            | `ARP -> output_private frame
            | `IPv4 -> (
              (* Takes an IPv4 packet [payload], unmarshal it, check if it's possible to
                 unmarshall it (if not, it may be a vertex coverage algorithm packet),
                 otherwise use the filter_rules to [out] the packet or not. *)
              match Ipv4_packet.Unmarshal.of_cstruct payload with
              | Result.Error _s ->
                  (* Logs.err (fun m -> m "Can't parse IPv4 packet: %s" s); *)
                  handle_special_packet header.source payload output_ipv4_private Public
              (* Otherwise try to forward (or not) the packet *)
              | Result.Ok (ipv4_hdr, payload) when Rules.filter filter_rules (ipv4_hdr, payload) ->
                  output_public frame
              | Result.Ok _ -> (* The packet is not forwardable according to the current ruleset *)
                  Lwt.return_unit
              )
            | _ -> Lwt.return_unit)
        | Error s ->
            Log.debug (fun f -> f "dropping Ethernet frame: %s" s);
            Lwt.return_unit
      in
      Public_net.listen ~header_size public_netif input >>= function
      | Error e ->
          Log.debug (fun f ->
              f "public interface stopped: %a" Public_net.pp_error e);
          Lwt.return_unit
      | Ok () ->
          Log.debug (fun f -> f "public interface terminated normally");
          Lwt.return_unit
    in

    let listen_private =
      let header_size = Ethernet.Packet.sizeof_ethernet
      and input frame =
        (* Takes an ethernet packet and send it to the relevant callback *)
        match Ethernet.Packet.of_cstruct frame with
        | Ok (header, payload) -> (
            match header.Ethernet.Packet.ethertype with
            | `ARP -> output_public frame
            | `IPv4 -> (
              (* Takes an IPv4 packet [payload], unmarshal it, check if it's possible to
                 unmarshall it (if not, it may be a vertex coverage algorithm packet),
                 otherwise use the filter_rules to [out] the packet or not. *)
              match Ipv4_packet.Unmarshal.of_cstruct payload with
              | Result.Error _s ->
                  (* Logs.err (fun m -> m "Can't parse IPv4 packet: %s" s); *)
                  (* handle_special_packet checks if that's really a vertex coverage packet *)
                  handle_special_packet header.source payload output_ipv4_public Private
              (* Otherwise try to forward (or not) the packet *)
              | Result.Ok (ipv4_hdr, payload) when Rules.filter filter_rules (ipv4_hdr, payload) ->
                  output_public frame
              | Result.Ok _ -> (* The packet is not forwardable according to the current ruleset *)
                  Lwt.return_unit
              )
            | _ -> Lwt.return_unit)
        | Error s ->
            Log.debug (fun f -> f "dropping Ethernet frame: %s" s);
            Lwt.return_unit
      in
      Private_net.listen ~header_size private_netif input >>= function
      | Error e ->
          Log.debug (fun f ->
              f "private interface stopped: %a" Private_net.pp_error e);
          Lwt.return_unit
      | Ok () ->
          Log.debug (fun f -> f "private interface terminated normally");
          Lwt.return_unit
    in

    (* Notice how we haven't said anything about ICMP anywhere.  The unikernel
       doesn't know anything about it, so pinging this host on either interface
       will just be ignored -- the only way this unikernel can be easily seen,
       without sending traffic through it, is via ARP.  The `arping` command
       line utility might be useful in trying to see whether your unikernel is
       up. *)

    Lwt.async (fun () -> send_packet_periodically output_ipv4_private 3);
    Lwt.async (fun () -> send_packet_periodically output_ipv4_public 3);

    (* start both listeners, and continue as long as both are working. *)
    Lwt.pick
      [
        listen_public;
        listen_private;
      ]
end
