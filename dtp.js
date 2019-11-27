// Support functions, in Javascript, for the DTP system (see /hhs/dtp.php)

function init()
{
 canvas = document.getElementById("mycanvas");  // our canvas
 ctx = canvas.getContext("2d");                 // our drawing context
 // convert width from mm into pixels as displayed on the page
 width_multiple = canvas.width / page_width;
 height_multiple = canvas.height / page_height;
} // end of init

var boxSize = 10;

// array position meanings
const ELEMENT_ID = 0;
const ELEMENT_TYPE = 1;
const DESCRIPTION = 2;
const STARTX = 3;
const STARTY = 4;
const ENDX = 5;
const ENDY = 6;

// element types
const ELEMENT_RECTANGLE= 1;
const ELEMENT_ELLIPSE = 2;
const ELEMENT_LINE = 3;
const ELEMENT_STAR = 4;
const ELEMENT_TEXT = 5;
const ELEMENT_IMAGE = 6;
const ELEMENT_TEXT_CONTINUATION = 7;

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
  element_id  = element [ELEMENT_ID];
  element_type = element [ELEMENT_TYPE];
  description = element [DESCRIPTION];
  startX      = element [STARTX];
  startY      = element [STARTY];
  endX        = element [ENDX];
  endY        = element [ENDY];

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

  } // end of for each element

} // end of drawborders

function onMouseMove(event)
{
  if (dragok)
   {
    // find new position in mm
    x = event.offsetX / width_multiple;
    y = event.offsetY  / height_multiple;

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

    drawborders ();

    element_id = elements [activeElement] [ELEMENT_ID];

    startXonPage = document.getElementsByName("element_".concat (element_id.toString (10), "_startX"));
    startXonPage [0].innerHTML = elements [activeElement] [STARTX];

    console.log ('Changing'.concat ('element_', element_id.toString (10), '_startX', ' to ' , elements [activeElement] [STARTX]));
   }  // if dragok
} // end of onMouseMove

function mouseInBox (mousex, mousey, x, y)
  {
  if (mousex < (x * width_multiple) - boxSize / 2)
    return false;  // too far left
  if (mousex > (x * width_multiple) + boxSize / 2)
    return false;  // too far right
  if (mousey < (y * height_multiple) - boxSize / 2)
    return false;  // too far up
  if (mousey > (y * height_multiple) + boxSize / 2)
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
    if (mouseInBox (mousex, mousey, startX, startY))
      {
      activeElement = i;
      activeCorner = 'topleft';
      found = true;
      }
    else if (mouseInBox (mousex, mousey, endX, startY))
      {
      activeElement = i;
      activeCorner = 'topright';
      found = true;
      }
    else if (mouseInBox (mousex, mousey, startX, endY))
      {
      activeElement = i;
      activeCorner = 'bottomleft';
      found = true;
      }
    else if (mouseInBox (mousex, mousey, endX, endY))
      {
      activeElement = i;
      activeCorner = 'bottomright';
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

drawborders ();
