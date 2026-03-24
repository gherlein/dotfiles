;;; init.el --- Greg Herlein's Emacs configuration -*- lexical-binding: t; -*-

;; Raise GC threshold during init, restore after
(setq gc-cons-threshold (* 50 1000 1000))
(add-hook 'emacs-startup-hook
          (lambda ()
            (setq gc-cons-threshold (* 2 1000 1000))
            (message "Emacs ready in %s with %d garbage collections."
                     (format "%.2f seconds"
                             (float-time
                              (time-subtract after-init-time before-init-time)))
                     gcs-done)))

;; Suppress "When done with a buffer, type C-x #"
(setq server-client-instructions nil)

;;; --- straight.el bootstrap ---

(defvar bootstrap-version)
(let ((bootstrap-file
       (expand-file-name
        "straight/repos/straight.el/bootstrap.el"
        (or (bound-and-true-p straight-base-dir)
            user-emacs-directory)))
      (bootstrap-version 7))
  (unless (file-exists-p bootstrap-file)
    (with-current-buffer
        (url-retrieve-synchronously
         "https://raw.githubusercontent.com/radian-software/straight.el/develop/install.el"
         'silent 'inhibit-cookies)
      (goto-char (point-max))
      (eval-print-last-sexp)))
  (load bootstrap-file nil 'nomessage))

(straight-use-package 'use-package)
(setq straight-use-package-by-default t)

;;; --- Terminal mouse support ---

(unless (display-graphic-p)
  (xterm-mouse-mode 1)
  (global-set-key (kbd "<mouse-4>") 'scroll-down-line)
  (global-set-key (kbd "<mouse-5>") 'scroll-up-line))
(setq select-enable-clipboard t)

;;; --- System clipboard in terminal (OSC 52) ---

(use-package clipetty
  :hook (after-init . global-clipetty-mode))

;;; --- Theme ---

(setq modus-vivendi-palette-overrides
      '((bg-main "#1a1a1a")))
(load-theme 'modus-vivendi t)

;;; --- Basic UI ---

(setq inhibit-startup-message t)
(setq inhibit-splash-screen t)
(menu-bar-mode -1)
(when (fboundp 'scroll-bar-mode) (scroll-bar-mode -1))
(when (fboundp 'tool-bar-mode) (tool-bar-mode -1))

(electric-indent-mode 0)
(global-font-lock-mode t)
(setq font-lock-maximum-decoration t)
(setq next-line-add-newlines nil)

;;; --- General settings ---

(setq vc-follow-symlinks nil)
(setq vc-consult-headers nil)
(fset 'yes-or-no-p 'y-or-n-p)
(setq major-mode 'text-mode)

;;; --- Paren matching ---

(require 'paren)
(show-paren-mode 1)
(setq show-paren-style 'parenthesis)

;;; --- Global keybindings ---

(global-set-key (kbd "<home>") 'beginning-of-line)
(global-set-key (kbd "<end>")  'end-of-line)
(global-set-key [f1] 'delete-other-windows)
(global-set-key [f2] 'save-buffer)
(global-set-key [f3] 'query-replace-regexp)
(global-set-key [f6] 'goto-line)
(global-set-key [f8] 'beginning-of-buffer)
(global-set-key [f9] 'end-of-buffer)

(global-set-key "%" 'match-paren)
(defun match-paren (arg)
  "Go to the matching parenthesis if on parenthesis, otherwise insert %."
  (interactive "p")
  (cond ((looking-at "\\s(") (forward-list 1) (backward-char 1))
        ((looking-at "\\s)") (forward-char 1) (backward-list 1))
        (t (self-insert-command (or arg 1)))))

;;; --- Completion ---

(use-package company
  :hook (after-init . global-company-mode)
  :config
  (setq company-idle-delay 0.2
        company-minimum-prefix-length 2))

;;; --- LSP (eglot is built into Emacs 29+) ---

(use-package eglot
  :straight nil
  :hook ((go-mode . eglot-ensure)
         (typescript-mode . eglot-ensure)
         (js-mode . eglot-ensure))
  :config
  (setq eglot-autoshutdown t))

;;; --- Go ---

(use-package go-mode
  :straight (:host github :repo "dominikh/go-mode.el")
  :mode "\\.go\\'"
  :bind (:map go-mode-map
              ("M-." . xref-find-definitions)
              ("M-*" . xref-go-back)
              ("M-p" . compile)
              ("<f4>" . beginning-of-defun)
              ("<f5>" . end-of-defun)
              ("<f7>" . go-indent-function))
  :config
  (setq gofmt-command "goimports")
  (add-hook 'go-mode-hook
            (lambda ()
              (add-hook 'before-save-hook #'gofmt-before-save nil t)
              (setq tab-width 4)
              (setq indent-tabs-mode t)
              (unless (string-match "go" compile-command)
                (setq-local compile-command "go build -v && go test -v && go vet")))))

(add-to-list 'exec-path "~/go/bin")

(defun go-indent-function ()
  "Find and mark the function boundaries and indent the region."
  (interactive)
  (let ((start (save-excursion
                 (re-search-backward "^func")
                 (point))))
    (save-excursion
      (re-search-forward "^}")
      (indent-region start (point) nil))))

;;; --- TypeScript ---

(use-package typescript-mode
  :straight (:host github :repo "emacs-typescript/typescript.el")
  :mode "\\.ts\\'")

;;; --- JavaScript / JSON ---

(use-package js2-mode
  :mode "\\.js\\'"
  :hook (js2-mode . js2-imenu-extras-mode)
  :config
  (setq js2-use-font-lock-faces t))

(use-package json-mode
  :mode "\\.json\\'")

(use-package js2-refactor
  :straight (:host github :repo "js-emacs/js2-refactor.el")
  :hook (js2-mode . js2-refactor-mode))

;;; --- Markdown ---

(use-package markdown-mode
  :mode "\\.md\\'"
  :hook (markdown-mode . visual-line-mode))

;;; --- YAML ---

(use-package yaml-mode
  :mode "\\.yml\\'"
  :bind (:map yaml-mode-map
              ("C-m" . newline-and-indent)))

;;; --- Docker ---

(use-package dockerfile-mode
  :mode "Dockerfile\\'")

(use-package docker-compose-mode
  :mode "docker-compose.*\\.yml\\'")

;;; --- Terraform / HCL ---

(use-package terraform-mode
  :mode "\\.tf\\'"
  :hook (terraform-mode . terraform-format-on-save-mode))

;;; --- Wrap region ---

(use-package wrap-region
  :straight (:host github :repo "rejeep/wrap-region.el")
  :hook (prog-mode . wrap-region-mode))

;;; --- Rainbow delimiters ---

(use-package rainbow-delimiters
  :hook (prog-mode . rainbow-delimiters-mode))

;;; --- BrightScript (Roku) ---

(use-package brightscript-mode
  :straight (:host github :repo "viseztrance/brightscript-mode")
  :mode "\\.brs\\'")

;;; --- OpenSCAD ---

(use-package scad-mode
  :straight (:host github :repo "openscad/emacs-scad-mode")
  :mode "\\.scad\\'")

;;; --- Arduino ---

(add-to-list 'auto-mode-alist '("\\.ino\\'" . c-mode))

;;; --- C/C++ style ---

(defconst my-c-style
  '((c-tab-always-indent        . t)
    (c-comment-only-line-offset  . 0)
    (c-hanging-braces-alist      . ((substatement-open after)
                                    (brace-list-open)))
    (c-hanging-colons-alist      . ((member-init-intro before)
                                    (inher-intro)
                                    (case-label after)
                                    (label after)
                                    (access-label after)))
    (c-cleanup-list              . (scope-operator
                                    empty-defun-braces
                                    defun-close-semi))
    (c-offsets-alist             . ((arglist-close . c-lineup-arglist)
                                    (substatement-open . 0)
                                    (case-label        . 2)
                                    (block-open        . 0)
                                    (knr-argdecl-intro . -)))
    (c-echo-syntactic-information-p . t)))

(defun my-c-mode-common-hook ()
  (require 'cc-mode)
  (c-add-style "PERSONAL" my-c-style t)
  (c-set-offset 'member-init-intro '++)
  (setq c-basic-offset 2)
  (setq c-default-style "bsd")
  (setq tab-width 2
        indent-tabs-mode nil)
  (c-toggle-auto-hungry-state 1)
  (define-key c-mode-base-map (kbd "RET") 'newline-and-indent))

(add-hook 'c-mode-common-hook #'my-c-mode-common-hook)

(defun c-reformat-buffer ()
  "Reformat buffer using GNU indent."
  (interactive)
  (save-buffer)
  (let ((indent-command (concat
                         "indent -st -bad --blank-lines-after-procedures "
                         "-bli0 -i4 -l79 -ncs -npcs -nut -npsl -fca "
                         "-lc79 -fc1 -cli4 -bap -sob -ci4 -nlp "
                         buffer-file-name)))
    (shell-command-on-region (point-min) (point-max) indent-command (buffer-name))
    (save-buffer)))

(global-set-key [f7] 'c-reformat-buffer)

(defun c-indent-function ()
  "Find and mark the function boundaries and indent the region."
  (interactive)
  (let ((start (save-excursion
                 (re-search-backward ") {$")
                 (point))))
    (save-excursion
      (re-search-forward "^}")
      (indent-region start (point) nil))))

;;; --- Custom-set isolation (keep at end) ---

(setq custom-file (expand-file-name "custom.el" user-emacs-directory))
(when (file-exists-p custom-file)
  (load custom-file))

;;; init.el ends here
