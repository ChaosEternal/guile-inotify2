(use-modules (linux inotify2))

(define iport (inotify-init))
(define wd (inotify-add-watch iport "/tmp/d" '(create delete)))

(display "create/delete some file in /tmp/d:\n")

(let lp ((i 10))
  (if (> i 0)
      (begin (display
	      (inotify-read-port iport))
	     (newline)
	     (lp (- i 1)))))
