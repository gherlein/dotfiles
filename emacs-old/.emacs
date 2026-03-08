;; Make startup faster by reducing the frequency of garbage
;; collection.  The default is 800 kilobytes.  Measured in bytes.
(setq gc-cons-threshold (* 50 1000 1000))

;; Make gc pauses faster by decreasing the threshold.
(setq gc-cons-threshold (* 2 1000 1000))

;; Use a hook so the message doesn't get clobbered by other messages.
(add-hook 'emacs-startup-hook
          (lambda ()
            (message "Emacs ready in %s with %d garbage collections."
                     (format "%.2f seconds"
                             (float-time
                              (time-subtract after-init-time before-init-time)))
                     gcs-done)))

;; supress warning When done with a buffer, type C-x #
(setq server-client-instructions nil)

;; add mouse support
;;;; Mouse scrolling in terminal emacs
(unless (display-graphic-p)
  ;; activate mouse-based scrolling
  (xterm-mouse-mode 1)
  (global-set-key (kbd "<mouse-4>") 'scroll-down-line)
  (global-set-key (kbd "<mouse-5>") 'scroll-up-line)
  )
(setq x-select-enable-clipboard t)


;; Add the melpa package repository
;; Remember to always use HTTPS
;;
(require 'package) ;; You might already have this line
(add-to-list 'package-archives
             '("melpa" . "https://melpa.org/packages/"))

(add-to-list 'load-path "~/elisp")
;;
;;
;; first, declare repositories
(setq package-archives
      '(("gnu" . "http://elpa.gnu.org/packages/")
	("melpa-stable" . "http://stable.melpa.org/packages/")
        ("marmalade" . "http://marmalade-repo.org/packages/")
        ("melpa" . "http://melpa.org/packages/")))

;; Init the package facility
(require 'package)
(package-initialize)
;;(package-refresh-contents) ;; this line is commented
;; since refreshing packages is time-consuming and should be done on demand

;; Declare packages
(setq my-packages
      '(markdown-mode
	docker-compose-mode
	dockerfile-mode
        wrap-region
        yaml-mode
        json-mode
	js2-mode
	js2-refactor
	xref-js2
	terraform-mode
	rainbow-delimiters
	go-mode
	dash
	s
;;	f
;;	editorconfig
	jsonrpc))

;; Iterate on packages and install missing ones
(dolist (pkg my-packages)
  (unless (package-installed-p pkg)
    (package-install pkg)))

;; copilot
;;(add-to-list 'load-path "~/elisp/copilot.el")
;;(require 'copilot)
;;(add-hook 'prog-mode-hook 'copilot-mode)
;;(define-key copilot-completion-map (kbd "<tab>") 'copilot-accept-completion)
;;(define-key copilot-completion-map (kbd "TAB") 'copilot-accept-completion)
;;(add-hook 'prog-mode-hook 'rainbow-delimiters-mode)

;; Configure basic startup
(setq inhibit-startup-message t)
(setq inhibit-splash-screen t)
(customize-set-variable 'menu-bar-mode nil)
;(customize-set-variable 'tool-bar-mode nil)
(customize-set-variable 'scroll-bar-mode nil)

;;(set-default-font "Menlo 10")

;; basic window setups
(electric-indent-mode 0)
(setq font-lock-maximum-decoration t)
(setq next-line-add-newlines nil)
(cond ((fboundp 'global-font-lock-mode)
              ;; Turn on font-lock in all modes that support it
              (global-font-lock-mode t)
              ;; Maximum colors
              (setq font-lock-maximum-decoration t)))

(require 'auto-complete )
(global-auto-complete-mode t)

(setq vc-follow-symlinks nil);
(setq vc-consult-headers nil);
(fset 'yes-or-no-p 'y-or-n-p)
(setq default-major-mode 'text-mode)

(require 'paren)
(show-paren-mode 1)
(setq show-paren-mode t)
(setq show-paren-style 'parenthesis)

;; keymaps
;;(global-set-key "^H"      'delete-backward-char)

(global-set-key (kbd "<home>") 'beginning-of-line)
(global-set-key (kbd "<end>")  'end-of-line)

(global-set-key [f1]      'delete-other-windows)
(global-set-key [f2]      'save-buffer)
;;(global-set-key [f3]      'recompile)
;;(global-set-key [f4]      'next-error)
;;(global-set-key [f5]      'previous-error)
(global-set-key [f3]      'query-replace-regexp)

(global-set-key [f6]      'goto-line)
(global-set-key [f7]      'c-reformat-buffer)

(global-set-key [f8]      'beginning-of-buffer)
(global-set-key [f9]      'end-of-buffer)

(add-to-list 'auto-mode-alist '("\\.ino$" . c-mode))
(add-to-list 'auto-mode-alist '("\\.pl$" . c-mode))
(add-to-list 'auto-mode-alist '("\\.pm$" . c-mode))

(autoload 'scad-mode "scad-mode" "A major mode for editing OpenSCAD code." t)
(add-to-list 'auto-mode-alist '("\\.scad$" . scad-mode))



(add-to-list 'load-path "~/elisp/terraform-mode")
(add-to-list 'load-path "~/elisp/emacs-hcl-mode")
(autoload 'terraform-mode "terraform-mode" t)
(autoload 'hcl-mode "hcl-mode" t)
(add-to-list 'auto-mode-alist '("\\.tf\\'" . terraform-mode))
(add-hook 'terraform-mode-hook 'terraform-format-on-save-mode)


(add-to-list 'load-path "~/elisp/markdown-mode")
(autoload 'markdown-mode "markdown-mode" t)
(add-to-list 'auto-mode-alist '("\\.md\\'" . markdown-mode))
(add-hook 'markdown-mode-hook 'turn-on-visual-line-mode)



;;(setq auto-mode-alist (append '(("\\.js$" . c-mode)) auto-mode-alist))
;;(setq auto-mode-alist (append '(("\\.ts$" . c-mode)) auto-mode-alist))
(autoload 'js2-mode "js2-mode" t)
(add-to-list 'auto-mode-alist '("\\.js$\\'" . js2-mode))
(add-to-list 'auto-mode-alist '("\\.ts$\\'" . js2-mode))
(add-to-list 'auto-mode-alist '("\\.ts\\'"  . js2-mode))
(add-to-list 'auto-mode-alist '("\\.json\\'" . js2-mode))
;;(setq js2-mode-show-strict-warnings nil)
(add-hook 'js2-mode-hook
          (lambda ()
	    (define-key js-mode-map (kbd "<f7>") 'json-pretty-print-buffer)))
;; Better imenu
(add-hook 'js2-mode-hook 'js2-imenu-extras-mode)
(setq js2-use-font-lock-faces t)


(autoload 'brightscript-mode "brightscript-mode" t)
(add-to-list 'auto-mode-alist '("\\.brs" . brightscript-mode))

(autoload 'yaml-mode "yaml-mode" t)
(add-to-list 'auto-mode-alist '("\\.yml" . yaml-mode))

;; golang stuff
(autoload 'go-mode "go-mode" t)
(add-hook 'go-mode-hook
          (lambda ()
            (add-hook 'before-save-hook 'gofmt-before-save)
            (setq tab-width 4)
            (setq indent-tabs-mode 1)))
(when window-system (set-exec-path-from-shell-PATH))
(add-to-list 'exec-path "~/go/bin")

(defun my-go-mode-hook ()
  (add-hook 'before-save-hook 'gofmt-before-save)
  (setq gofmt-command "goimports")
  (if (not (string-match "go" compile-command))   ; set compile command default
      (set (make-local-variable 'compile-command)
           "go build -v && go test -v && go vet"))

  ;; Key bindings specific to go-mode
  (local-set-key (kbd "M-.") 'godef-jump)         ; Go to definition
  (local-set-key (kbd "M-*") 'pop-tag-mark)       ; Return from whence you came
  (local-set-key (kbd "M-p") 'compile)            ; Invoke compiler
  (local-set-key (kbd "M-.") 'godef-jump)
  (local-set-key (kbd "M-*") 'pop-tag-mark)
  (local-set-key (kbd "<f7>") 'go-indent-function)
  (local-set-key (kbd "<f4>") 'beginning-of-defun)
  (local-set-key (kbd "<f5>") 'end-of-defun)

  ;; Misc go stuff
  (auto-complete-mode 1))                         ; Enable auto-complete mode

(add-hook 'go-mode-hook 'my-go-mode-hook)
(defun auto-complete-for-go ()
  (auto-complete-mode 1))
(add-hook 'go-mode-hook 'auto-complete-for-go)

;(add-hook 'text-mode-hook 'turn-on-auto-fill)
(defconst my-c-style
  '((c-tab-always-indent        . t)
    (c-comment-only-line-offset . 0)
    (c-hanging-braces-alist     . ((substatement-open after)
				   (brace-list-open)))
    (c-hanging-colons-alist     . ((member-init-intro before)
				   (inher-intro)
				   (case-label after)
				   (label after)
				   (access-label after)))
    (c-cleanup-list             . (scope-operator
				   empty-defun-braces
				   defun-close-semi))
    (c-offsets-alist            . ((arglist-close . c-lineup-arglist)
				   (substatement-open . 0)
				   (case-label        . 2)
				   (block-open        . 0)
				   (knr-argdecl-intro . -)))
    (c-echo-syntactic-information-p . t)
    )
  )

(defun my-c-mode-common-hook ()
  ;; add my personal style and set it for the current buffer
  (require 'cc-mode)
  (c-add-style "PERSONAL" my-c-style t)
  ;; offset customizations not in my-c-style
  (c-set-offset 'member-init-intro '++)
  (setq c-basic-offset 2)
  (setq-default c-basic-offset 2 c-default-style "linux")
  (setq c-default-style "bsd")
  ;; other customizations
  (setq tab-width 2
	;; this will make sure spaces are used instead of tabs
	indent-tabs-mode nil)
  (c-toggle-auto-hungry-state 1)
  (define-key c-mode-base-map "\C-m" 'newline-and-indent)
  (add-hook 'c-mode-common-hook '(lambda () (c-toggle-auto-state 1)))
  (define-key c-mode-base-map (kbd "RET") 'newline-and-indent)
  )
(add-hook 'c-mode-common-hook 'my-c-mode-common-hook)
(add-hook 'c-mode-common-hook '(lambda () (font-lock-mode 1)))


(defun c-reformat-buffer()
    (interactive)
    (save-buffer)
    (setq sh-indent-command (concat
                             "indent -st -bad --blank-lines-after-procedures "
                             "-bli0 -i4 -l79 -ncs -npcs -nut -npsl -fca "
                             "-lc79 -fc1 -cli4 -bap -sob -ci4 -nlp "
                             buffer-file-name
                             )
          )
    (mark-whole-buffer)
    (universal-argument)
    (shell-command-on-region
     (point-min)
     (point-max)
     sh-indent-command     (buffer-name)
     )
    (save-buffer)
    )

;;(define-key c-mode-base-map [f7] 'c-reformat-buffer)





;;
(add-hook 'yaml-mode-hook
	  (lambda ()
	    (define-key yaml-mode-map "\C-m" 'newline-and-indent)))

(defun go-indent-function ()
  "Find and mark the function boundaries and indent the region."
  (interactive)
  (re-search-backward "^func" )
  (setq start (point))
  (re-search-forward "^}" )
  (indent-region start (point) nil)
)

(defun c-indent-function ()
  "Find and mark the function boundaries and indent the region."
  (interactive)
  (re-search-backward ") {$" )
  (setq start (point))
  (re-search-forward "^}" )
  (indent-region start (point) nil)
)


(global-set-key "%" 'match-paren)
(defun match-paren (arg)
  "Go to the matching parenthesis if on parenthesis otherwise insert %."
  (interactive "p")
  (cond ((looking-at "\\s\(") (forward-list 1) (backward-char 1))
        ((looking-at "\\s\)") (forward-char 1) (backward-list 1))
        (t (self-insert-command (or arg 1)))))








(custom-set-variables
 ;; custom-set-variables was added by Custom.
 ;; If you edit it by hand, you could mess it up, so be careful.
 ;; Your init file should contain only one such instance.
 ;; If there is more than one, they won't work right.
 '(package-selected-packages
   '(rainbow-delimiters json-mode yaml-mode wrap-region paredit markdown-mode)))
(custom-set-faces
 ;; custom-set-faces was added by Custom.
 ;; If you edit it by hand, you could mess it up, so be careful.
 ;; Your init file should contain only one such instance.
 ;; If there is more than one, they won't work right.
 )
