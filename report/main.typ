#text(2em)[D0029E Lab 2 - Group Green M 3]

Members:
- Arvid Persson
- Joel Andersson
- Rasmus Engström

#set heading(
  numbering: (..n) => {
    let number = n.pos().map(str).join(".")
    [Task #number]
  },
  supplement: [],
)

=

// WARN: doesn't handle subsections, or appendices beyond "Z".
#counter(heading).update(0)
#set heading(
  numbering: (..n) => {
    let a = "A".to-unicode()
    let offset = n.pos().first()
    [Appendix #str.from-unicode(a + offset - 1)]
  },
  supplement: []
)
#pagebreak()

