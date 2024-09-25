let log = Logs.Src.create "rules" ~doc:"FW rules management"
module Log = (val Logs.src_log log : Logs.LOG)

type decision =
  | ACCEPT
  | DROP
  (* TODO:
  | ESTABLISHED
  | RELATED will need more work... *)

type rule = {
  src : Ipaddr.V4.Prefix.t ;
  psrc : int ;
  dst : Ipaddr.V4.Prefix.t ;
  pdst : int ;
  proto : Ipv4_packet.protocol option ;
  action : decision option ;
}

let rule_to_string r =
  String.concat " " [
    Ipaddr.V4.Prefix.to_string r.src ;
    ":" ;
    begin match r.psrc with
    | 0 -> "ANY"
    | x -> Int.to_string x
    end ;
    "->" ;
    Ipaddr.V4.Prefix.to_string r.dst ;
    ":" ;
    begin match r.pdst with
    | 0 -> "ANY"
    | x -> Int.to_string x
    end ;
    "(" ;
    begin match r.proto with
    | Some `TCP -> "TCP"
    | Some `UDP -> "UDP"
    | Some `ICMP -> "ICMP"
    | None -> "ANY"
    end ;
    ") :" ;
    begin match r.action with
    | Some ACCEPT -> "ACCEPT"
    | Some DROP -> "DROP"
    | None -> "XXX" (* Should not be printed ever... add an assert false?*)
    end ;
  ]

(* A match is either the target is joker or the ip is in the target network *)
let match_ip ip target =
  target = Ipaddr.V4.Prefix.global || Ipaddr.V4.Prefix.mem ip target

type cb = Ipaddr.V4.t * Cstruct.t -> unit Lwt.t

type t = {
  mutable l : rule list ;
  default : bool;
}

let init default =
  {l = [{src = Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; psrc=0; dst=Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; pdst=7070; proto=Some `TCP; action=Some ACCEPT};
        {src = Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; psrc=7070; dst=Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; pdst=0; proto=Some `TCP; action=Some ACCEPT};
        {src = Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; psrc=0; dst=Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; pdst=8080; proto=Some `UDP; action=Some ACCEPT};
        {src = Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; psrc=0; dst=Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; pdst=0; proto=Some `ICMP; action=Some ACCEPT};
        {src = Ipaddr.V4.Prefix.of_string_exn "10.0.0.0/24"; psrc=0; dst=Ipaddr.V4.Prefix.of_string_exn "224.0.0.251/32"; pdst=0; proto=Some `UDP; action=Some ACCEPT};
        {src = Ipaddr.V4.Prefix.global; psrc=0; dst=Ipaddr.V4.Prefix.global; pdst=0; proto=None; action=Some DROP}];
        default}

(* Here we apply, for easy testing, a default to accept last ressort rule :x
let default_accept cb (dest, packet) =
  Log.debug (fun f -> f "Default rule accept packet to %a..." Ipaddr.V4.pp dest);
  cb (dest, packet)

(* The default to drop last ressort rule would be *)
let default_drop _cb (dest, _packet) =
  Log.debug (fun f -> f "Default rule drop packet to %a..." Ipaddr.V4.pp dest);
  Lwt.return_unit *)

(* The update packet is (as a UDP packet):
   2B port source + 2B port dest + 2B len + 2B crc
   + 4B magic string "1234"
   + 1B insert or append (INSERT=0, APPEND=1)
   + 1B number of the following
     + 4B IP source (all 0s is joker)
     + 4B IP dest (all 0s is joker)
     + 1B source netmask (0 is joker) + 1B destination netmask (0 is joker)
     + 2B port source (0 is joker)
     + 2B destination source (0 is joker)
     + 1B the protocol code (ICMP=1, TCP=6, UDP=17, ANY=other values)
     + 1B the decision (0=DROP, 1=ACCEPT, anything else is a failure)

   One can send such a packet with:
     python -c "import sys; sys.stdout.buffer.write(bytearray([49, 50, 51, 52, 0, 2, 10, 11, 12, 13, 192, 168, 0, 0, 24, 24, 0, 53, 0, 0, 6, 0, 172, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 1]))" | nc -u 10.0.0.2 1234
   This would append the rules:
     10.11.12.13/24 : 53 -> 192.168.0.0/24 : ANY ( TCP ) : DROP
     172.16.0.0/12 : ANY -> 0.0.0.0/0 : ANY ( ANY ) : ACCEPT
*)
let magic_hdr = Int32.of_string "0x31323334"

let magic_is_present payload =
  Cstruct.BE.get_uint16 payload 2 = 1234 && (* our port must be 1234 *)
  Cstruct.BE.get_uint32 payload 8 = magic_hdr
  (* I currently don't bother to check the crc... *)

let update t payload =
  (* Skip the UDP header *)
  let payload = Cstruct.shift payload 8 in
  let ins_or_app = Cstruct.get_uint8 payload 4 in
  if ins_or_app <> 0 && ins_or_app <> 1 then
    Log.err(fun f -> f "Don't know what to do with the rules")
  else begin
    let n = Cstruct.get_uint8 payload 5 in

    let rec extract_rule acc payload =
      let rule_size = 16 in
      if Cstruct.length payload < rule_size then
        (* TODO: what is the expected behaviour if there is not already consummed data? *)
        acc
      else begin
        let src = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 payload 0) in  
        let dst = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 payload 4) in

        let src_mask = Cstruct.get_uint8 payload 8 in
        let src = Ipaddr.V4.Prefix.make src_mask src in
        let dst_mask = Cstruct.get_uint8 payload 9 in
        let dst = Ipaddr.V4.Prefix.make dst_mask dst in

        let psrc = Cstruct.BE.get_uint16 payload 10 in
        let pdst = Cstruct.BE.get_uint16 payload 12 in
  
        let proto = match Cstruct.get_uint8 payload 14 with
          | 1 -> Some `ICMP
          | 6 -> Some `TCP
          | 17 -> Some `UDP
          | _ -> None (* FIXME: distinguish a value error from a special ANY case? *)
        in
        let action = match Cstruct.get_uint8 payload 15 with
          | 0 -> Some DROP
          | 1 -> Some ACCEPT
          | _ -> None
        in

        let r = {src ; dst ; psrc ; pdst ; proto ; action} in
        (* Fail on the first unrecognized rule *)
        if action = None then begin
          Log.err(fun f -> f "Cannot recognize rule: %s" (rule_to_string r));
          []
        end else begin
          Log.debug(fun f -> f "Recognized rule: %s" (rule_to_string r));
          extract_rule (r::acc) (Cstruct.shift payload rule_size)
        end
      end
    in

    let r = extract_rule [] (Cstruct.shift payload 6) in

    match ins_or_app, r with
    | _, _ when List.length r <> n ->
      Log.err(fun f -> f "Not enough rules %d vs. %d" (List.length r) n)
    | 0, r ->
      t.l <- List.append r t.l
    | 1, r ->
      t.l <- List.append t.l r
    | _, _ ->
      Log.err(fun f -> f "Don't know chat to do with the rules");
      assert false; (* The code should not go there...*)
  end

  let is_matching_port packet proto r_psrc r_pdst = 
      match r_psrc, r_pdst, proto with
      | 0, 0, _ -> true
      | _, _, 6 -> (
          (* TCP *)
          match Tcp.Tcp_packet.Unmarshal.of_cstruct packet with
          | Result.Error s ->
              Logs.err (fun m -> m "Can't parse TCP packet: %s" s);
              false
          | Result.Ok (tcp_hdr, _payload) ->
              (r_psrc = 0 || tcp_hdr.src_port = r_psrc) && (r_pdst = 0 || tcp_hdr.dst_port = r_pdst)
        )
      | _, _, 17 -> (
          (* UDP *)
          match Udp_packet.Unmarshal.of_cstruct packet with
          | Result.Error s ->
              Logs.err (fun m -> m "Can't parse UDP packet: %s" s);
              false
          | Result.Ok (udp_hdr, _payload) ->
              (r_psrc = 0 || udp_hdr.src_port = r_psrc) && (r_pdst = 0 || udp_hdr.dst_port = r_pdst)
        )
      | _, _, 1 -> true (* ICMP *)
      | _ -> true



(* Takes an ipv4 header [ipv4_hdr] and the whole IPv4 [packet] (containing the header).
   We want to filter out any packet matching the [filters] list, and if not filtered,
   transfer it (unchanged) to [forward_to].
   NOTE: We know the packet is not for us. *)
let filter t (ipv4_hdr, packet) =
  let rec apply_rules
  : bool -> (Ipv4_packet.t * Cstruct.t) -> rule list -> bool
  = fun default (ipv4_hdr, packet) filter_rules ->
    match filter_rules with
    (* If the list is empty -> apply default action *)
    | [] -> default
    (* default_cb forward_to (ipv4_hdr.dst, packet) *)

    (* If the packet matches the condition and has an accept action *)
    | {src; psrc; dst; pdst; proto; action=Some ACCEPT}::_ when
        match_ip ipv4_hdr.src src && match_ip ipv4_hdr.dst dst &&
        (proto = None || Ipv4_packet.Unmarshal.int_to_protocol ipv4_hdr.Ipv4_packet.proto = proto) && is_matching_port packet ipv4_hdr.Ipv4_packet.proto psrc pdst
        (* TODO: also check the ports :) *)
      -> 
        Log.debug (fun f -> f "Accept a packet from %a to %a..." Ipaddr.V4.pp ipv4_hdr.src Ipaddr.V4.pp ipv4_hdr.dst);
        true

    (* Otherwise the packet matches and the action is drop *)
    | {src; psrc; dst; pdst; proto; action=Some DROP}::_ when
        match_ip ipv4_hdr.src src && match_ip ipv4_hdr.dst dst &&
        (proto = None || Ipv4_packet.Unmarshal.int_to_protocol ipv4_hdr.Ipv4_packet.proto = proto) && is_matching_port packet ipv4_hdr.Ipv4_packet.proto psrc pdst
        (* TODO: also check the ports :) *)
      -> 
        Log.debug (fun f -> f "Filter out a packet from %a to %a..." Ipaddr.V4.pp ipv4_hdr.src Ipaddr.V4.pp ipv4_hdr.dst);
        false

    (* Or finally the packet does not match the condition *)
    | _::tail -> apply_rules default (ipv4_hdr, packet) tail
  in

  apply_rules t.default (ipv4_hdr, packet) t.l
