// Support functions, in Javascript, for the DTP system (see /hhs/dtp.php)


const boxSize = 10;   // size of corner boxes
const draggingBoxSize = 30;  // size of dragging box

// array position meanings
const ELEMENT_ID = 0;
const ELEMENT_TYPE = 1;
const DESCRIPTION = 2;
const STARTX = 3;
const STARTY = 4;
const ENDX = 5;
const ENDY = 6;

const LAST_ITEM = ENDY;  // must be last element in array (above)

// element types
const ELEMENT_RECTANGLE= 1;
const ELEMENT_ELLIPSE = 2;
const ELEMENT_LINE = 3;
const ELEMENT_STAR = 4;
const ELEMENT_TEXT = 5;
const ELEMENT_IMAGE = 6;
const ELEMENT_TEXT_CONTINUATION = 7;

function init()
  {
  canvas = document.getElementById("mycanvas");  // our canvas
  ctx = canvas.getContext("2d");                 // our drawing context
  // convert width from mm into pixels as displayed on the page
  width_multiple = canvas.width / page_width;
  height_multiple = canvas.height / page_height;

  orig_elements = [];
  for (i = 0; i < num_elements; i++)
    {
    orig_elements [i] = [];
    for (j = 0; j < LAST_ITEM; j++)
      orig_elements [i] [j] = elements [i] [j];
    }
  edit_clicked = false
  } // end of init

function drawCornerBox (x, y)
  {
  ctx.beginPath();
  ctx.rect((x * width_multiple)   - boxSize / 2,
           (y * height_multiple)  - boxSize / 2,
           boxSize,
           boxSize
           );
  ctx.fillStyle = "green";
  ctx.fill ();
  } // end of drawCornerBox

function getElementDetails (element)
  {
  // extract out fields from database
  element_id    = element [ELEMENT_ID];
  element_type  = element [ELEMENT_TYPE];
  description   = element [DESCRIPTION];
  startX        = element [STARTX];
  startY        = element [STARTY];
  endX          = element [ENDX];
  endY          = element [ENDY];

  } // end of getElementDetails

function drawborders ()
{
ctx.clearRect(0, 0, canvas.width, canvas.height);  // clear canvas
for (i = 0; i < num_elements; i++)
  {
  // get *this* element
  getElementDetails (elements [i]);

  // stroke the entire element (box around it)
  ctx.beginPath();
  ctx.rect(startX * width_multiple, startY * height_multiple, (endX - startX) * width_multiple, (endY - startY) * height_multiple);
  ctx.strokeStyle = "green";
  ctx.stroke();

  // corner boxes (small boxes at corners)
  drawCornerBox (startX, startY);

  // lines only have two corners
  if (element_type != ELEMENT_LINE)
    {
    drawCornerBox (endX, startY);
    drawCornerBox (startX, endY);
    }

  drawCornerBox (endX, endY);

  // draw dragging box

  ctx.beginPath();
  x = startX + ((endX - startX) / 2);  // half way along
  ctx.rect((x * width_multiple) - (draggingBoxSize / 2),
           (startY * height_multiple)  - boxSize / 2,
           draggingBoxSize,
           boxSize
           );
  ctx.fillStyle = "green";
  ctx.fill ();

  } // end of for each element

} // end of drawborders

function ResetClicked (event)
{
  submit_edits_button = document.getElementById("submit_edits_button");
  submit_edits_button.disabled = true;
  reset_edits_button = document.getElementById("reset_edits_button");
  reset_edits_button.disabled = true;

  for (i = 0; i < num_elements; i++)
    {
    // copy values back
    for (j = 0; j < LAST_ITEM; j++)
      elements [i] [j] = orig_elements [i] [j];

    // put the HTML values back
    element_id = elements [i] [ELEMENT_ID];

    // fix up startX
    startXonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_startX"));
    startXonPage [0].value = elements [i] [STARTX];

    // fix up startY
    startYonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_startY"));
    startYonPage [0].value = elements [i] [STARTY];

    // fix up endX
    endXonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_endX"));
    endXonPage [0].value = elements [i] [ENDX];

    // fix up endY
    endYonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_endY"));
    endYonPage [0].value = elements [i] [ENDY];

    } // end of for each element

  drawborders ();   // redraw original positions
  return false;     // don't submit form
} // end of ResetClicked

function SubmitEditsClicked (event)
{
  if (!edit_clicked)
    {
    edit_clicked = true;
    submit_edits_button = document.getElementById("submit_edits_button");
    submit_edits_button.value = "Submit Edits";
    submit_edits_button.disabled = true;  // nothing edited yet
    drawborders ();
    return false;   // don't submit yet
    }
  return true;  // submit form now
} // end of SubmitEditsClicked

function onMouseMove(event)
{
  if (dragok)
   {
    // find new position in mm
    x = Math.round(event.offsetX / width_multiple);
    y = Math.round(event.offsetY  / height_multiple);

    // update element

    if (activeCorner == 'topleft')
      {
      if (x < elements [activeElement] [ENDX] && y < elements [activeElement] [ENDY])
        {
        elements [activeElement] [STARTX] = x;
        elements [activeElement] [STARTY] = y;
        }
      }
    else if (activeCorner == 'topright')
      {
      if (x > elements [activeElement] [STARTX] && y < elements [activeElement] [ENDY])
        {
        elements [activeElement] [ENDX] = x;
        elements [activeElement] [STARTY] = y;
        }
      }
    else if (activeCorner == 'bottomleft')
      {
      if (x < elements [activeElement] [ENDX] && y > elements [activeElement] [STARTY])
        {
        elements [activeElement] [STARTX] = x;
        elements [activeElement] [ENDY] = y;
        }
      }
   else if (activeCorner == 'bottomright')
      {
      if (x > elements [activeElement] [STARTX] && y > elements [activeElement] [STARTY])
        {
        elements [activeElement] [ENDX] = x;
        elements [activeElement] [ENDY] = y;
        }
      }
    else if (activeCorner == 'drag')
      {
      deltaX = Math.round((dragStartX - event.offsetX) / width_multiple);
      deltaY = Math.round((dragStartY - event.offsetY) / height_multiple);
      dragStartX = event.offsetX;
      dragStartY = event.offsetY;
      elements [activeElement] [STARTX] -= deltaX;
      elements [activeElement] [STARTY] -= deltaY;
      elements [activeElement] [ENDX]   -= deltaX;
      elements [activeElement] [ENDY]   -= deltaY;
      }

    drawborders ();

    // update form ready for them to post it

    // turn element array number into an element ID
    element_id = elements [activeElement] [ELEMENT_ID];

    // fix up startX
    startXonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_startX"));
    startXonPage [0].value = elements [activeElement] [STARTX];

    // fix up startY
    startYonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_startY"));
    startYonPage [0].value = elements [activeElement] [STARTY];

    // fix up endX
    endXonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_endX"));
    endXonPage [0].value = elements [activeElement] [ENDX];

    // fix up endY
    endYonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_endY"));
    endYonPage [0].value = elements [activeElement] [ENDY];

    submit_edits_button = document.getElementById("submit_edits_button");
    submit_edits_button.disabled = false;
    reset_edits_button = document.getElementById("reset_edits_button");
    reset_edits_button.disabled = false;
    reset_edits_button.onclick = ResetClicked;

 //   console.log ('Changing '.concat ('element_', element_id.toString (10), '_startX', ' to ' , elements [activeElement] [STARTX]));
 //   console.log ('Changing '.concat ('element_', element_id.toString (10), '_endX', ' to ' ,   elements [activeElement] [ENDX]));
 //   console.log ('Changing '.concat ('element_', element_id.toString (10), '_startY', ' to ' , elements [activeElement] [STARTY]));
 //   console.log ('Changing '.concat ('element_', element_id.toString (10), '_endY', ' to ' , elements [activeElement] [ENDY]));
   }  // if dragok
} // end of onMouseMove

function mouseInBox (mousex, mousey, x, y, size)
  {
  if (mousex < (x * width_multiple) - size / 2)
    return false;  // too far left
  if (mousex > (x * width_multiple) + size / 2)
    return false;  // too far right
  if (mousey < (y * height_multiple) - size / 2)
    return false;  // too far up
  if (mousey > (y * height_multiple) + size / 2)
    return false;  // too far down
  return true;
  } // end of mouseInBox

function onMouseDown(event)
{
  found = false;
  mousex = event.offsetX;
  mousey = event.offsetY;
//  console.log ("event".concat (' x= ', event.offsetX, ' y= ', event.offsetY));

  // find active element
  for (i = 0; i < num_elements; i++)
    {
    // get *this* element
    getElementDetails (elements [i]);
    if (mouseInBox (mousex, mousey, startX, startY, boxSize))
      {
      activeElement = i;
      activeCorner = 'topleft';
      found = true;
      }
    else if (mouseInBox (mousex, mousey, endX, startY, boxSize))
      {
      activeElement = i;
      activeCorner = 'topright';
      found = true;
      }
    else if (mouseInBox (mousex, mousey, startX, endY, boxSize))
      {
      activeElement = i;
      activeCorner = 'bottomleft';
      found = true;
      }
    else if (mouseInBox (mousex, mousey, endX, endY, boxSize))
      {
      activeElement = i;
      activeCorner = 'bottomright';
      found = true;
      }
    // and now check the dragging box
    else if (mouseInBox (mousex, mousey, startX + (endX - startX) / 2, startY, draggingBoxSize))
      {
      activeElement = i;
      activeCorner = 'drag';
      dragStartX = mousex;
      dragStartY = mousey;
      found = true;
      }

    } // end of for each element

  if (!found)
    {
//    console.log ("no element found");
    return;
    }

//  shiftX = event.clientX - ball.getBoundingClientRect().left;
//  shiftY = event.clientY - ball.getBoundingClientRect().top;

  dragok = true;
  canvas.onmousemove = onMouseMove;
} // end of onMouseDown

function onMouseUp()
{
 dragok = false;
 canvas.onmousemove = null;
}

init ();  // get our canvas and context

// mouse handlers
canvas.onmousedown = onMouseDown;
canvas.onmouseup = onMouseUp;
