;;; scad-mode.el --- A major mode for editing OpenSCAD code

;; Author:     Len Trigg, Lukasz Stelmach
;; Maintainer: Len Trigg <lenbok@gmail.com>
;; Created:    March 2010
;; Modified:   28 Mar 2015
;; Keywords:   languages
;; URL:        https://raw.github.com/openscad/openscad/master/contrib/scad-mode.el
;; Version:    91.0

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2 of the License, or
;; (at your option) any later version.

;;; Code:

;;;###autoload
(add-to-list 'auto-mode-alist '("\\.scad$" . scad-mode))

(require 'cc-mode)

(defcustom scad-command
  '"openscad"
  "Path to openscad executable."
  :type 'string)

(defcustom scad-keywords
  '("return" "true" "false")
  "SCAD keywords."
  :type 'list
  :group 'scad-font-lock)

(defcustom scad-functions
  '("cos" "acos" "sin" "asin" "tan" "atan" "atan2"
    "abs" "sign" "rands" "min" "max"
    "round" "ceil" "floor"
    "pow" "sqrt" "exp" "log" "ln"
    "str"
    "lookup" "version" "version_num" "len" "search"
    "dxf_dim" "dxf_cross"
    "norm" "cross"
    "concat" "chr")
  "SCAD functions."
  :type 'list
  :group 'scad-font-lock)

(defcustom scad-modules
  '("children" "echo" "for" "intersection_for" "if" "else"
    "cube" "sphere" "cylinder" "polyhedron" "square" "circle" "polygon"
    "scale" "rotate" "translate" "mirror" "multmatrix"
    "union" "difference" "intersection"
    "render"
    "color"
    "surface"
    "linear_extrude"
    "rotate_extrude"
    "import"
    "group"
    "projection"
    "minkowski" "glide" "subdiv" "hull" "resize"
    "parent_module"
    "let" "offset" "text")
  "SCAD modules."
  :type 'list
  :group 'scad-font-lock)

(defcustom scad-deprecated
  '("child" "assign" "dxf_linear_extrude" "dxf_rotate_extrude"
    "import_stl" "import_off" "import_dxf")
  "SCAD deprecated modules and functions."
  :type 'list
  :group 'scad-font-lock)

(defcustom scad-operators
  '("+" "-" "*" "/" "%"
    "&&" "||" "!"
    "<" "<=" "==" "!=" ">" ">="
    "?" ":" "=")
  "SCAD operators."
  :type 'list
  :group 'scad-font-lock)

(defvar scad-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map [(control c) (control o)] 'scad-open-current-buffer)
    (define-key map [return] 'newline-and-indent)
    map)
  "Keymap for `scad-mode'.")

(defvar scad-mode-syntax-table
  (let ((st (make-syntax-table)))
    (modify-syntax-entry ?\/ ". 124b" st)
    (modify-syntax-entry ?\n "> b" st)
    (modify-syntax-entry ?* ". 23" st)
    (modify-syntax-entry ?+  "." st)
    (modify-syntax-entry ?-  "." st)
    (modify-syntax-entry ?%  "." st)
    (modify-syntax-entry ?<  "." st)
    (modify-syntax-entry ?>  "." st)
    (modify-syntax-entry ?&  "." st)
    (modify-syntax-entry ?:  "." st)
    (modify-syntax-entry ?|  "." st)
    (modify-syntax-entry ?=  "." st)
    (modify-syntax-entry ?\;  "." st)
    st)
  "Syntax table for `scad-mode'.")

(defvar scad-keywords-regexp (regexp-opt scad-keywords 'words))
(defvar scad-modules-regexp (regexp-opt scad-modules 'words))
(defvar scad-functions-regexp (regexp-opt scad-functions 'words))
(defvar scad-deprecated-regexp (regexp-opt scad-deprecated 'words))
(defvar scad-operators-regexp (regexp-opt scad-operators))

(defvar scad-font-lock-keywords
  `(("\\(module\\|function\\)[ \t]+\\(\\sw+\\)" (1 'font-lock-keyword-face nil) (2 'font-lock-function-name-face nil t))
    ("\\(use\\|include\\)[ \t]*<\\([^>]+\\)>" (1 'font-lock-preprocessor-face nil) (2 'font-lock-type-face nil t))
    ("<\\(\\sw+\\)>" (1 'font-lock-builtin-face nil))
    ("$\\(\\sw+\\)" (1 'font-lock-builtin-face nil))
    (,scad-keywords-regexp . font-lock-keyword-face)
    (,scad-modules-regexp .  font-lock-builtin-face)
    (,scad-functions-regexp .  font-lock-function-name-face)
    (,scad-deprecated-regexp .  font-lock-warning-face))
  "Keyword highlighting specification for `scad-mode'.")
(defconst scad-font-lock-keywords-1 scad-font-lock-keywords)
(defconst scad-font-lock-keywords-2 scad-font-lock-keywords)
(defconst scad-font-lock-keywords-3 scad-font-lock-keywords)

(defvar scad-indent-style nil
  "The style of indentation for scad-mode.
Defaults to \"k&r\" if nil.")

(put 'scad-mode 'c-mode-prefix "scad-")
;;;###autoload
(define-derived-mode scad-mode prog-mode "SCAD"
  "Major mode for editing OpenSCAD code."
  (c-initialize-cc-mode)
  (use-local-map scad-mode-map)
  (c-set-offset (quote cpp-macro) 0 nil)
  (c-basic-common-init 'scad-mode (or scad-indent-style "k&r"))
  (c-font-lock-init)
  (c-run-mode-hooks 'c-mode-common-hook 'scad-mode-hook)
  (c-update-modeline))

(defun scad-prime-dabbrev ()
  "Make a hidden buffer with SCAD keywords for dabbrev expansion."
  (unless (get-buffer " *scad words*")
    (with-current-buffer (get-buffer-create " *scad words*")
      (scad-mode)
      (insert "module function use include")
      (insert (mapconcat 'identity (append scad-keywords scad-functions scad-modules scad-deprecated) " ")))))
(add-hook 'scad-mode-hook 'scad-prime-dabbrev)

(defun scad-open-current-buffer ()
  "Open current buffer in OpenSCAD."
  (interactive)
  (call-process scad-command nil 0 nil (buffer-file-name)))

(provide 'scad-mode)
;;; scad-mode.el ends here
