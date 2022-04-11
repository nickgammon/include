-- Custom writer for Nick's DTP system

-- Written by Nick Gammon
-- Date: July 2019



--[[

PURPOSE

This is the pandoc output formatting Lua script, designed to be called by pandoc like this:

  pandoc (stdin) --from=markdown+smart -t /var/www/include/svg_pandoc_outputter.lua --metadata=indent:3 (stdout) --metadata=line_after:$line_after

This is done when text fields are added/changed by the "validation" field in the standard database editor
for the column "Text_Contents". The results (SVG text) is stored in the "Text_Contents_SVG" column.

Therefore changes to the indenting will only apply if that text box is resubmitted (edited).

INDENTS

Note regarding indents:

The simpler method of indenting would be to use styles, like left-margin:3px; however Inkscape
does not seem to be honouring the rendering of such.

I have been forced to literally insert spaces at the start of paragraphs (except the first, and
except after line breaks, horizontal lines, and headings).

The number of spaces is passed in as metadata: PANDOC_DOCUMENT.meta.indent
This is done when invoking pandoc: --metadata=indent:$indent

It was hard to find the right space character. Most worked fine for non-justified text but failed
with justified text because additional spaces were inserted at the start of lines (ie. in the indent)
depending on the number of spaces being used to justify the text. This made paragraph starts not line
up.

I finally (after much research) found U+2800 which prints as a space but does not interfere with
justification (as it is "not a space").

LINES AFTER PARAGRAPHS

If the style requires a blank line after paragraphs then PANDOC_DOCUMENT.meta.line_after should be non-zero.

This is done when invoking pandoc: --metadata=line_after:$line_after

----

https://en.wikipedia.org/wiki/Whitespace_character

The Braille Patterns Unicode block contains U+2800 ⠀ BRAILLE PATTERN BLANK (HTML &#10240;),
a Braille pattern with no dots raised. Some fonts display the character as a fixed-width blank,
however the Unicode standard explicitly states that it does not act as a space.

--]]

local INDENT_SPACE = '&#x2800;'  -- U+2800 ⠀ BRAILLE PATTERN BLANK (HTML &#10240;),

-- Character escaping
local function escape(s, in_attribute)
  return s:gsub("[<>&\"']",
    function(x)
      if x == '<' then
        return '&lt;'
      elseif x == '>' then
        return '&gt;'
      elseif x == '&' then
        return '&amp;'
      elseif x == '"' then
        return '&quot;'
      elseif x == "'" then
        return '&#39;'
      else
        return x
      end
    end)
end

-- Helper function to convert an attributes table into
-- a string that can be put into HTML tags.
local function attributes(attr)
  local attr_table = {}
  for x,y in pairs(attr) do
    if y and y ~= "" then
      table.insert(attr_table, ' ' .. x .. ':' .. escape(y,true) .. '; ')
    end
  end
  return table.concat(attr_table)
end

-- Run cmd on a temporary file containing inp and return result.
local function pipe(cmd, inp)
  local tmp = os.tmpname()
  local tmph = io.open(tmp, "w")
  tmph:write(inp)
  tmph:close()
  local outh = io.popen(cmd .. " " .. tmp,"r")
  local result = outh:read("*all")
  outh:close()
  os.remove(tmp)
  return result
end

-- Table to store footnotes, so they can be included at the end.
local notes = {}

-- First paragraph is not indented
local firstPara = true
local lineBreak = false
local firstHeading = true

-- Blocksep is used to separate block elements.
function Blocksep()
  return "\n\n"
end

-- This function is called once for the whole document. Parameters:
-- body is a string, metadata is a table, variables is a table.
-- This gives you a fragment.  You could use the metadata table to
-- fill variables in a custom lua template.  Or, pass `--template=...`
-- to pandoc, and pandoc will add do the template processing as
-- usual.
function Doc(body, metadata, variables)
  return body .. table.concat(notes,'\n') .. '\n'
end

-- The functions that follow render corresponding pandoc elements.
-- s is always a string, attr is always a table of attributes, and
-- items is always an array of strings (the items in a list).
-- Comments indicate the types of other variables.

function Str(s)
  return escape(s)
end

function Space()
  return " "
end

function SoftBreak()
  return " "
end

function LineBreak()
  lineBreak = true
  return "<flowPara></flowPara>\n"
end

function Emph(s)
  return '<flowSpan style="font-style:italic" >' .. s .. "</flowSpan>"
end

function Strong(s)
  return '<flowSpan style="font-weight:bold" >' .. s .. "</flowSpan>"
end

function Subscript(s)
  return '<flowSpan style="font-size:65%;baseline-shift:sub; " >' .. s .. "</flowSpan>"
end



function Superscript(s)
  return '<flowSpan style="font-size:65%;baseline-shift:super; " >' .. s .. "</flowSpan>"
end

function SmallCaps(s)
  return '<span style="font-variant: small-caps;">' .. s .. '</span>'
end

-- NOT WORKING!
function Strikeout(s)
  return '<flowSpan style="text-decoration: line-through; " >' .. s .. "</flowSpan>"
end

function Link(s, src, tit, attr)
  return "<a href='" .. escape(src,true) .. "' title='" ..
         escape(tit,true) .. "'>" .. s .. "</a>"
end

function Image(s, src, tit, attr)
  return "<img src='" .. escape(src,true) .. "' title='" ..
         escape(tit,true) .. "'/>"
end

function Code(s, attr)
  return '<flowSpan style="font-family:monospace;" >' .. s .. "</flowSpan>"
end

function InlineMath(s)
  return "\\(" .. escape(s) .. "\\)"
end

function DisplayMath(s)
  return "\\[" .. escape(s) .. "\\]"
end

function trim(s)
   return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function Note(s)
  local num = #notes + 1
  -- add a list item with the note to the note table.
  table.insert(notes, num ..  ". " .. string.gsub (s, INDENT_SPACE, ''))
  -- return the footnote reference, linked to the note.
  return '<flowSpan style="font-size:65%;baseline-shift:super; " >' .. num .. "</flowSpan>"
end

function Span(s, attr)
  return "<flowSpan style=\" " .. attributes(attr) .. "\">" .. s .. "</flowSpan>"
end

function RawInline(format, str)
  if format == "html" then
    return str
  else
    return ''
  end
end

function Cite(s, cs)
  local ids = {}
  for _,cit in ipairs(cs) do
    table.insert(ids, cit.citationId)
  end
  return "<span class=\"cite\" data-citation-ids=\"" .. table.concat(ids, ",") ..
    "\">" .. s .. "</span>"
end

function Plain(s)
  return s
end

function Para(s)
  -- replace indent amount with Unicode en-dash size spaces (of indent_amount number)
  local indent_amount = PANDOC_DOCUMENT.meta.indent or 0
  if firstPara then
    indent_amount = 0
    firstPara = false
  end -- if
  if lineBreak then
    firstPara = true
    lineBreak = false
  end -- if
  firstPara = false
  firstHeading = false

  local extra_line
  if PANDOC_DOCUMENT.meta.line_after and tonumber (PANDOC_DOCUMENT.meta.line_after) ~= 0 then
    extra_line = '<flowPara>' .. '</flowPara>'
  else
    extra_line = ''
  end -- if

  return  '<flowPara>' .. string.rep (INDENT_SPACE, indent_amount) .. s .. "</flowPara>" ..
          extra_line .. '\n'
end

-- lev is an integer, the header level.
function Header(lev, s, attr)
  attr.id = nil  -- don't want that (the name)

  firstPara = true -- start unindented after a heading

  if #s == 0 then
    heading = LineBreak ()
  else
    if firstHeading then
      heading = ''
    else
      heading = LineBreak ()
    end -- if
    heading =  heading ..  -- blank line before unless first paragraph
               '<flowPara><flowSpan style="font-size:' ..
               (6 - lev) * 2 + 10 ..
               '; font-weight:bold;' ..
               attributes(attr) ..   -- convert attributes into a list, eg. fill:blue;
               ' " >' .. s .. "</flowSpan></flowPara>" ..
               LineBreak () .. "\n"  -- blank line after

  end -- if

  lineBreak = false
  firstHeading = false
  return heading
end

function BlockQuote(s)
  return "<blockquote>\n" .. s .. "\n</blockquote>"
end

function HorizontalRule()
  firstPara = true -- start unindented after a heading
  local rule =  LineBreak () ..  -- blank line before
                 "<flowPara>" .. string.rep ('―', 10) .. "</flowPara>" ..
                 LineBreak () .. "\n"  -- blank line after
  lineBreak = false
  return rule
end

function LineBlock(ls)
  return '<div style="white-space: pre-line;">' .. table.concat(ls, '\n') ..
         '</div>'
end

function CodeBlock(s, attr)
  return '<flowSpan style="font-family:monospace;" >' .. s .. "</flowSpan>"
end

-- Note that if you have a blank line between bullet points (making a paragraph) and indenting is on
-- then the indent will occur *after* the bullet point because "item" is already indented.

-- FIX: I have removed INDENT_SPACE from items so that this doesn't happen, it looks weird.

function BulletList(items)
  local buffer = {}
  for _, item in pairs(items) do
    item = string.gsub (item, INDENT_SPACE, '')  -- get rid of indentations
    table.insert(buffer, '<flowPara >•' .. INDENT_SPACE .. item .. "</flowPara>")  -- xml:space="preserve"
  end
  return table.concat(buffer, "\n")
end

function OrderedList(items)
  local buffer = {}
  for i, item in pairs(items) do
    item = string.gsub (item, INDENT_SPACE, '')  -- get rid of indentations
    table.insert(buffer, i .. ". " .. item )
  end
  return "\n" .. table.concat(buffer, "\n") .. "\n"
end

-- Revisit association list STackValue instance.
function DefinitionList(items)
  local buffer = {}
  for _,item in pairs(items) do
    for k, v in pairs(item) do
      table.insert(buffer,"<dt>" .. k .. "</dt>\n<dd>" ..
                        table.concat(v,"</dd>\n<dd>") .. "</dd>")
    end
  end
  return "<dl>\n" .. table.concat(buffer, "\n") .. "\n</dl>"
end

-- Convert pandoc alignment to something HTML can use.
-- align is AlignLeft, AlignRight, AlignCenter, or AlignDefault.
function html_align(align)
  if align == 'AlignLeft' then
    return 'left'
  elseif align == 'AlignRight' then
    return 'right'
  elseif align == 'AlignCenter' then
    return 'center'
  else
    return 'left'
  end
end

function CaptionedImage(src, tit, caption, attr)
   return '<div class="figure">\n<img src="' .. escape(src,true) ..
      '" title="' .. escape(tit,true) .. '"/>\n' ..
      '<p class="caption">' .. caption .. '</p>\n</div>'
end

-- Caption is a string, aligns is an array of strings,
-- widths is an array of floats, headers is an array of
-- strings, rows is an array of arrays of strings.
function Table(caption, aligns, widths, headers, rows)
  local buffer = {}
  local function add(s)
    table.insert(buffer, s)
  end
  add("<table>")
  if caption ~= "" then
    add("<caption>" .. caption .. "</caption>")
  end
  if widths and widths[1] ~= 0 then
    for _, w in pairs(widths) do
      add('<col width="' .. string.format("%d%%", w * 100) .. '" />')
    end
  end
  local header_row = {}
  local empty_header = true
  for i, h in pairs(headers) do
    local align = html_align(aligns[i])
    table.insert(header_row,'<th align="' .. align .. '">' .. h .. '</th>')
    empty_header = empty_header and h == ""
  end
  if empty_header then
    head = ""
  else
    add('<tr class="header">')
    for _,h in pairs(header_row) do
      add(h)
    end
    add('</tr>')
  end
  local class = "even"
  for _, row in pairs(rows) do
    class = (class == "even" and "odd") or "even"
    add('<tr class="' .. class .. '">')
    for i,c in pairs(row) do
      add('<td align="' .. html_align(aligns[i]) .. '">' .. c .. '</td>')
    end
    add('</tr>')
  end
  add('</table')
  return table.concat(buffer,'\n')
end

function RawBlock(format, str)
  if format == "html" then
    return str
  else
    return ''
  end
end

function Div(s, attr)
  return "<div" .. attributes(attr) .. ">\n" .. s .. "</div>"
end

function DoubleQuoted(s)
  return "“" .. s .. "”"
end

function SingleQuoted(s)
  return "‘" .. s .. "’"
end

-- The following code will produce runtime warnings when you haven't defined
-- all of the functions you need for the custom writer, so it's useful
-- to include when you're working on a writer.
local meta = {}
meta.__index =
  function(_, key)
    io.stderr:write(string.format("WARNING: Undefined function '%s'\n",key))
    return function() return "" end
  end
setmetatable(_G, meta)

