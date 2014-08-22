lightsec
========

Python implementation of the protocol described in Naranjo et al. (2013).


Protocol
--------

<img src="http://rawgithub.com/gomezgoiri/lightsec/master/docs/diagram.svg" alt="Protocol diagram" >

1. At the time of sensor deployment, the latter receives a master secret _MS<sub>S</sub>_, which is secretly shared by the Base Station _BS_ and the sensor _S_ (see the end of this section for secret channels).
1. Upon arrival, user _A_ sends her credentials (e.g. an authorization certificate) to BS so high-level access control can be performed, and the list of sensors she wants to communicate with (in the figure we only consider _S_). This step is run only at user arrival.
1. BS computes:
 1. a, random integer salt
 1. (init time, exp time), keying material validity interval
 1. _Kenc<sub>S,A</sub>_ , _Kauth<sub>S,A</sub>_ = KDF (_MS<sub>S</sub>_, {a, IDA &#124;&#124; init time &#124;&#124; exp time_})

1. _BS_ sends the information generated in the previous step to _A_ under a secure channel (see the end of this section).
1. _A_ encrypts her first message to _S_ with _Kenc<sub>S,A</sub>_ in counter mode (thus using a fresh counter _ctr_), attaches parameters _ID<sub>A</sub>_ , _a_, _init time_, _exp time_, _ctr_ in plain text and a MAC obtained with _Kauth<sub>S,A</sub>_.
1. Upon reception of the message, _S_ obtains the key pair _Kenc<sub>S,A</sub>_, _Kauth<sub>S,A</sub>_ by feeding the Key Derivation Function with the attached parameters; _S_ can now decrypt the message. The reply is encrypted in counter mode with _Kenc<sub>S,A</sub>_ and _ctr + 1_ and authenticated with a MAC using _Kauth<sub>S,A</sub>_.
1. Any subsequent message is encrypted and authenticated with the same key pair after increasing the counter by one.



Notation
--------

Symbol         | Explanation
-------------- | ------------------------------
Kenc<sub>S,A</sub> |  Encryption key for communication between sensor S and user A
Kauth<sub>S,A</sub> |  Authentication key for communication between sensor S and user A
Kenc<sub>S,A</sub> {x, ctr} |  _x_ is encrypted in counter mode using key _Kenc<sub>S,A</sub>_ and counter _ctr_
MAC<sub>KauthS,A</sub> (x) |  A MAC is done on _x_ using _Kauth<sub>S,A</sub>_
KDF (x, {a, b}) |  A Key Derivation Function is applied to master secret _x_ using _a_ as public salt and _b_ as user-related information
H(x) |  A hash function is applied to _x_
x&#124;&#124;y | Concatenation of _x_ and _y_
_a_ | Random integer salt
ID<sub>A</sub> |  Identifier of user _A_
ID<sub>p</sub> |  Identifier of privilege group _p_
MS<sub>S</sub> |  Master secret for sensor S
MS<sub>p</sub> | Master secret for privilege group _p_
init_time |  Absolute initial time of a given key
exp_time |  Expiration time of a given key
Kenc<sub>p,A</sub> |  Encryption key for communication between sensors offering services for group p and user A
Kauth<sub>p,A</sub> |  Authentication key for communication between sensors offering services for group p and user A
A → * | User _A_ sends a message to any listening sensor
S<sub>p</sub> → A |  One sensor giving services from privilege group _p_ sends a message to _A_



Bibliography
------------

J. A. M. Naranjo, Pablo Orduña, Aitor Gómez-Goiri, Diego López-de-Ipiña, L. G. Casado. Enabling user access control in energy-constrained wireless smart environments. [Journal of Universal Computer Science](http://www.jucs.org/), [Volume 19](http://www.jucs.org/jucs_19), [number 17](http://www.jucs.org/jucs_19_17), [Pages 2490-2505](http://www.jucs.org/jucs_19_17/enabling_user_access_control), November 2013.
