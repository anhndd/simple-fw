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
    (Clock : Mirage_clock.MCLOCK) =
struct
  (* configure logs, so we can use them later *)
  let log = Logs.Src.create "fw" ~doc:"FW device"

  module Log = (val Logs.src_log log : Logs.LOG)

  (* the specific impls we're using show up as arguments to start. *)
  let start public_netif private_netif _public_ethernet _private_ethernet _rng
      () =
    (* Creates a set of rules (empty) and a default condition (accept) *)
    let filter_rules = Rules.init false in

    (* Takes an IPv4 [packet], unmarshal it, check if we're the destination and
       the payload is some sort of rule update, apply that, and if we're not the
       destination, use the filter_rules to [out] the packet or not. *)
    let is_forwardable packet =
      (* Handle IPv4 only... *)
      match Ipv4_packet.Unmarshal.of_cstruct packet with
      | Result.Error s ->
          Logs.err (fun m -> m "Can't parse IPv4 packet: %s" s);
          false
      (* Otherwise try to forward (or not) the packet *)
      | Result.Ok (ipv4_hdr, payload) ->
          Rules.filter filter_rules (ipv4_hdr, payload)
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
            | `IPv4 when is_forwardable payload -> output_private frame
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
            | `IPv4 when is_forwardable payload -> output_public frame
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

    (* start both listeners, and continue as long as both are working. *)
    Lwt.pick [ listen_public; listen_private ]
end
