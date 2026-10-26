; benchmark generated from python API
(set-info :status unknown)
(declare-fun width () Int)
(assert
 (let (($x579 (forall ((index Int) )(let (($x103 (>= 0 index)))
(let (($x48 (>= index 1)))
(let (($x104 (and $x48 $x103)))
(not $x104)))))
))
(let (($x25 (<= width 65535)))
(let (($x23 (>= width 1)))
(and $x23 $x25 (not (and $x23 $x25 (<= 0 width) $x579)))))))
(check-sat)
