lightsec
========

Python implementation of the protocol described in Naranjo et al. (2013).



Protocol
--------


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
