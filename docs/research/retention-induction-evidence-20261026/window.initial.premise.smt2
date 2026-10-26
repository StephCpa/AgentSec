; benchmark generated from python API
(set-info :status unknown)
(declare-fun width () Int)
(assert
 (let (($x25 (<= width 65535)))
(let (($x23 (>= width 1)))
(and $x23 $x25))))
(check-sat)
