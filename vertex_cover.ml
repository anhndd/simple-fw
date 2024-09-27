let log = Logs.Src.create "vertex_cover" ~doc:"vertex cover management"
module Log = (val Logs.src_log log : Logs.LOG)

type status =
| INITIATE
| COMPUTING

type command =
| PROB
| REPLY
| PROPOSE
| ACCEPT
| UNKNOWN

let command_to_int cmd =
  match cmd with
  | PROB -> 0
  | REPLY -> 1
  | PROPOSE -> 2
  | ACCEPT -> 3
  | UNKNOWN -> 10

  let int_to_command value =
    match value with
    | 0 -> PROB
    | 1 -> REPLY
    | 2 -> PROPOSE
    | 3 -> ACCEPT
    | _ -> UNKNOWN

type message = {
  cmd : command ;
}

type interface =
| Public
| Private

type unik_neigh = {
  inter: interface;
}

module MacMap = struct
  include Map.Make(Macaddr)
  let find x map =
    try Some (find x map)
    with Not_found -> None
    | _ -> Logs.err( fun f -> f "uncaught exception in find...%!"); None
end

type t = {
  mutable state : status;
  mutable degree: int;
  mutable map_unik_neighbor: unik_neigh MacMap.t
}

let init state = {state; degree = 0; map_unik_neighbor = MacMap.empty}

let update_degree t map_unik_neighbor =
    t.degree <- MacMap.cardinal map_unik_neighbor

let serialize_message cmd =
  let msg = {cmd} in
  (* Determine the size needed for the message:
     - cmd is an int (assuming 4 bytes) *)
  let size = 4 in
  let buf = Cstruct.create size in
  Cstruct.set_uint8 buf 0 (command_to_int msg.cmd);
  buf

let parse_message buf =
  let cmd = Cstruct.get_uint8 buf 0 in
  int_to_command cmd