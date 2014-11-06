
(define-module (linux inotify2)
  #:use-module (system foreign)
  #:use-module (ice-9 binary-ports)
  #:export (inotify-init 
	    inotify-add-watch
	    inotify-rm-watch
	    inotify-flags
	    inotify-flags->int
	    inotify-int->flags
	    inotify-read-port))

(define libc (dynamic-link ))

(define c-inotify-init
  (pointer->procedure int
		      (dynamic-func "inotify_init" libc)
		      '()))
(define c-inotify-init1
  (pointer->procedure int
		      (dynamic-func "inotify_init1" libc)
		      (list int)))
(define c-inotify-add-watch
  (pointer->procedure int
		      (dynamic-func "inotify_add_watch" libc)
		      (list int '*  uint32)))

(define c-inotify-rm-watch
  (pointer->procedure int
		      (dynamic-func "inotify_rm_watch" libc)
		      (list int int)))

(define (inotify-init)
  (fdes->inport (c-inotify-init)))

(define init-flags
  '((cloexec #o2000000)
    (nonblock #o4000)))

(define (inotify-init1 flag)
  (fdes->inport (c-inotify-init1 (in-inotify-flags->int flag init-flags))))

(define (inotify-add-watch port file-path flags)
  (let ((fd (port->fdes port))
	(fnptr (string->pointer file-path))
	(flag (inotify-flags->int flags)))
    (c-inotify-add-watch fd fnptr flag)))

(define (inotify-rm-watch port wd)
  (c-inotify-rm-watch (port->fdes port) wd))

(define struct-inotify-event
  (list int uint32 uint32 uint32))

(define size-struct-inotify-event
  (sizeof struct-inotify-event))

(define inotify-flags 
  '((access        #x00000001)  
    (modify        #x00000002)  
    (attrib        #x00000004)  
    (close-write   #x00000008)  
    (close-nowrite #x00000010)  
    (open          #x00000020)  
    (moved-from    #x00000040)  
    (moved-to      #x00000080)  
    (create        #x00000100)  
    (delete        #x00000200)  
    (delete-self   #x00000400)  
    (move-self     #x00000800)  

    (unmount       #x00002000)  
    (q-overflow    #x00004000)  
    (ignored       #x00008000)  

    (onlydir       #x01000000)  
    (dont-follow   #x02000000)  
    (excl-unlink   #x04000000)  
    (mask-add      #x20000000)  
    (isdir         #x40000000)  
    (oneshot       #x80000000)))  

(define (in-inotify-flags->int l flags-assoc)
  (let lp ((flags l)
	   (calced-flags 0))
    (if (null? flags)
	calced-flags
	(lp (cdr flags)
	    (logior calced-flags
		    (cadr 
		     (assoc (car flags)
			    flags-assoc)))))))
(define (inotify-flags->int l)
  (in-inotify-flags->int l inotify-flags))

(define (inotify-int->flags flag)
  (map (lambda (x) (car x))
       (filter (lambda (x)
		 (logtest (cadr x) flag))
	       inotify-flags)))

(define (inotify-read-port port)
  (let* ((bv (get-bytevector-n port size-struct-inotify-event))
	 (parsed (parse-c-struct (bytevector->pointer bv)
				 struct-inotify-event))
	 (wd (list-ref parsed 0))
	 (mask (list-ref parsed 1))
	 (cookie (list-ref parsed 2))
	 (len (list-ref parsed 3))
	 (name (pointer->string 
		   (bytevector->pointer
		    (get-bytevector-n port len)))))
    
    (list 
     (list 'wd wd)
     (list 'mask (inotify-int->flags mask))
     (list 'cookie cookie)
     (list 'name name))))
