##########################################################
# Threat Model Makefile, © 2025 Free & Fair              #
# Daniel M. Zimmerman, January 2025                      #
##########################################################
# Possible commands are: make [all|db|latex|pdf|clean

# Definitions

LATEXMK_CMD :=      latexmk --pdf
LATEX_INPUTS :=     ./latex_inputs
SRC_DIR :=          ./src
DIAGRAMS_DIR :=			./diagrams
VIEW_CMD :=         python -m nxt.model.view_cli
GEN_LATEX_CMD :=    python -m nxt.model.generate_latex_inputs
GEN_HTML_CMD :=     python -m nxt.model.generate_html
HTML_FILE :=        threat-model.html
BROWSER_CMD :=      open
THREAT_MODEL_DOC := threat-model

# Default target: show the help
all: help

# Display a brief help page listing possible targets.
help:
	@echo "Valid targets are:"
	@echo "help (default) - display this help page"
	@echo "latex          - generate all LaTeX inputs"
	@echo "pdf            - build the threat model PDF"
	@echo "html           - build the interactive threat model HTML"
	@echo "view           - run a smoketest of the command-line view of the model"
	@echo ""
	@echo "clean          - remove all generated files"
	@echo ""
	@echo "This Makefile assumes the diagrams are up to date, as they are"
	@echo "included in the repository. To rebuild the diagrams after changes,"
	@echo "use the Makefile in ${DIAGRAMS_DIR}"
	@echo ""

# Build static representations
static: pdf html

# Build the LaTeX inputs
latex:
	@echo "generating LaTeX inputs"
	mkdir -p ${LATEX_INPUTS}
	PYTHONPATH=${SRC_DIR} ${GEN_LATEX_CMD} --output ${LATEX_INPUTS}

# Build the PDF, including generating its dependencies
pdf: latex ${THREAT_MODEL_DOC}.tex references.bib
	@echo "generating threat model PDF"
	${LATEXMK_CMD} -halt-on-error -synctex=1 ${THREAT_MODEL_DOC}.tex

# Run a single smoketest of the command-line view of the model.
view:
	@echo "running an example view of the threat model"
	PYTHONPATH=${SRC_DIR} ${VIEW_CMD} -e attack -r "clash_attack_v2" -t

# Build the interactive HTML representation
html:
	@echo "generating interactive HTML representation"
	PYTHONPATH=${SRC_DIR} ${GEN_HTML_CMD} -o ${HTML_FILE}

# Clean the directory
clean:
	rm -rf ${LATEX_INPUTS}
	rm -f ${THREAT_MODEL_DOC}.pdf ${HTML_FILE}
	${LATEXMK_CMD} -bibtex-cond1 -C ${THREAT_MODEL_DOC}.tex

PHONY: all help db latex pdf html view clean
