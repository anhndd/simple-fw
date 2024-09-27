(* mirage >= 4.7.0 & < 4.8.0 *)
open Mirage

(* we need two network interfaces: a public side and a private side *)
(* a bit of magic: currently, multiple networks only work on Unix and Xen
   backends, so we can get away with this indexes-as-numbers-as-strings
   silliness.
   See https://github.com/mirage/mirage/issues/645 *)
let public_netif =
  Key.(if_impl is_solo5
         (netif ~group:"public" "public")
         (netif ~group:"public" "0"))
let private_netif =
  Key.(if_impl is_solo5
         (netif ~group:"private" "private")
         (netif ~group:"private" "1"))

(* build ethernet interfaces on top of those network interfaces *)
let public_ethernet = ethif public_netif
let private_ethernet = ethif private_netif

let packages = [
  package "ethernet";
  package "ipaddr";
  package ~min:"8.2.0" ~sublibs:["ipv4";"tcp"] "tcpip"; (* There was a breaking API changes in the 8.2 series *)
  package "logs";
  (* package ~min:"4.0.0" "mirage-runtime"; *) (* We want to avoid runtime argument at any cost *)
  package "duration";
]

(* our unikernel needs to know about physical network, and ethernet modules
   for each interface. Even though these modules will be the same for both
   interfaces in our case, we have to pass them separately. *)
let main = main "Unikernel.Main" ~packages
           (network  @-> network  @->
            ethernet @-> ethernet @->
            random   @-> mclock   @->
            time     @-> job)

(* we need to pass each of the network-related impls we've made to the
   unikernel, so that it can start the appropriate listeners. *)
let () = register "simple-fw" [ main
                                 $ public_netif    $ private_netif
                                 $ public_ethernet $ private_ethernet
                                 $ default_random  $ default_monotonic_clock
                                 $ default_time
                               ]
