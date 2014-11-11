
(define-module (linux inotify2)
  #:use-module (system foreign)
  #:use-module (ice-9 binary-ports)
  #:use-module (rnrs bytevectors)
  #:export (inotify-init 
	    inotify-init1
	    inotify-add-watch
	    inotify-rm-watch
	    inotify-flags
	    inotify-flags->int
	    inotify-int->flags
	    inotify-read-port))

"simple wrapper for inotify
WARNNING: errno is unreliable"

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

(define c-errno-pointer (dynamic-pointer "errno" (dynamic-link))) 

(define struct-inotify-event
  (list int uint32 uint32 uint32))

(define size-struct-inotify-event
  (sizeof struct-inotify-event))

(define init-flags
  '((cloexec #o2000000)
    (nonblock #o4000)))

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

(define (call-and-check-errno proc procname)
  (call-with-values 
      (lambda ()
	(call-with-blocked-asyncs
	 (lambda ()
	   (values
	    (proc)
	    (car  (parse-c-struct
		   ((pointer->procedure 
		     '*
		     (dynamic-pointer "__errno_location" (dynamic-link))
		     '()))
		   (list int)))))))
    (lambda (return-code errno)
      (if (< return-code 0)
	  (scm-error 'system-error procname (strerror errno) #f (list errno))
	  return-code))))

(define (inotify-flags->int l)
  (in-inotify-flags->int l inotify-flags))



(define (inotify-init1 flag)
  "- Scheme Procedure: inotify-init1 flag

     init inotify port using flag
     flag: list of 'cloexec, 'nonblock or just '() 

     return a port
     raise 'system-error on failure
"
  (fdes->inport 
   (call-and-check-errno 
    (lambda ()
      (c-inotify-init1 (in-inotify-flags->int flag init-flags)))
    "inotify-init1")))

(define (inotify-init)
  "- Scheme Procedure: inotify-init1 flag

     init inotify port

     return a port
     raise 'system-error on failure
"
  (inotify-init1 '()))

(define (inotify-add-watch port file-path flags)
   "- Scheme Procedure: inotify-add-watch port file-path flags

      adds a watch on file-path
      port: port returned by inotify-init or inotify-init1
      file-path: file or directory to watch
      flags: list of watch flag
      valid flags:
                  access       
                  modify       
                  attrib       
                  close-write  
                  close-nowrite
                  open         
                  moved-from   
                  moved-to     
                  create       
                  delete       
                  delete-self  
                  move-self    
                  unmount      
                  q-overflow   
                  ignored      
                  onlydir      
                  dont-follow  
                  excl-unlink  
                  mask-add     
                  isdir        
                  oneshot 

     return: watch descriptor
     raise 'system-error on failure                    
" 
  (let ((fd (port->fdes port))
	(fnptr (string->pointer file-path))
	(flag (inotify-flags->int flags)))
    (call-and-check-errno 
     (lambda () (c-inotify-add-watch fd fnptr flag))
     "inotify-add-watch")))

(define (inotify-rm-watch port wd)
  "- Scheme Procedure: inotify-rm-watch port wd

      remove watch `wd' from inotify port `port'
      port: port returned by inotify-init or inotify-init1
      wd: watch-descriptor returned by inotify-add-watch

      return 0 on success
      raise 'system-error on failure
    "
  (let ((inotify-fd (port->fdes port)))
    (call-and-check-errno (lambda ()
			    (c-inotify-rm-watch inotify-fd wd))
			  "inotify-rm-watch")))


(define (inotify-int->flags flag)
  (map (lambda (x) (car x))
       (filter (lambda (x)
		 (logtest (cadr x) flag))
	       inotify-flags)))


(define (inotify-read-port port)
  "- Scheme Procedure: inotify-read-port port 

      read an event from inotify port `port'
      port: port returned by inotify-init or inotify-init1

     return: ((wd `watch-descriptor') (mask `(list of flags)') (cookie `cookie') (name `file-name'))
   "
  (define (read-bv-and-check-length port length)
    (let* ([bv (make-bytevector length)]
	   [nread (get-bytevector-n! port bv 0 length)])
      (if (or (eof-object? nread) (< nread length))
	  (scm-error 'read-error "inotify-read-port" "not reading enough bytes" #f '()) 
	  bv)))
  (let* ((bv (read-bv-and-check-length port size-struct-inotify-event))
	 (parsed (parse-c-struct (bytevector->pointer bv)
				 struct-inotify-event))
	 (wd (list-ref parsed 0))
	 (mask (list-ref parsed 1))
	 (cookie (list-ref parsed 2))
	 (len (list-ref parsed 3))
	 (name (if (> len 0)
		   (pointer->string 
		    (bytevector->pointer
		     (read-bv-and-check-length port len)))
		   "")))
    
    (list 
     (list 'wd wd)
     (list 'mask (inotify-int->flags mask))
     (list 'cookie cookie)
     (list 'name name))))
