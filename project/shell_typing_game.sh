#!/bin/bash

function dis_welcome() {
  declare -r str='
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
1000000010000000101111101000000111100111000000100000001000001111
0100000101000001001000001000001000001000100001010000010100001000
0010001000100010001111101000001000001000100010001000100010001111
0001010000010100001000001000001000001000100100000101000001001000
0000100000001000001111101111100111100111001000000010000000101111
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000001111000000100000000001000000010000001111100000000000
0000000000010000000001010000000010100000101000001000000000000000
0000000000010011000011111000000100010001000100001111100000000000
0000000000010001000100000100001000001010000010001000000000000000
0000000000001111001000000010010000000100000001001111100000000000
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000000'
  declare -i j=0
  declare -i row=3   # Print start line.
  line_char_count=65 # Define the newline position, 64 characters per line plus newlines, for a total of 65 characters.

  echo -ne "\033[37;40m\033[5;3H" # Set the color and cursor start position.

  for ((i = 0; i < ${#str}; i++)); do
    # Line feed.
    if [ "$((i % line_char_count))" == "0" ] && [ "$i" != "0" ]; then
      row=$row+1
      echo -ne "\033["$row";3H"
    fi
    # Determine foreground and background characters.
    if [ "${str:$i:1}" == "0" ]; then
      echo -ne "\033[37;40m "
    elif [ "${str:$i:1}" == "1" ]; then
      echo -ne "\033[31;40m$"
    fi
  done
}

function dismenu() {
  while [ 1 ]; do
    draw_border
    echo -e "\033[8;30H1) Practice typing numbers"
    echo -e "\033[9;30H2) Practice typing letter"
    echo -e "\033[10;30H3) Practice alphanumeric mixing"
    echo -e "\033[11;30H4) Practice typing word"
    echo -e "\033[12;30H5) Exit"
    echo -ne "\033[22;2HPlease input your choice: "
    read choice
    case $choice in
      "1")
        draw_border
        #The last two are function parameters, the first parameter represents the typing type, and the second is the move character function.
        main digit
        echo -e "\033[39;49m"
        ;;
      "2")
        draw_border
        main char
        echo -e "\033[39;49m"
        ;;
      "3")
        draw_border
        main mix
        echo -e "\033[39;49m"
        ;;
      "4")
        draw_border
        echo -ne "\033[22;2H"
        read -p "Which file do you want to use for typing game practice: " file
        if [ ! -f "$file" ]; then
          dismenu
        else
          exec 4< $file # Create a file pipeline.
          main word
          echo -e "\033[39;49m"
        fi
        ;;
      "5" | "q" | "Q")
        draw_border
        echo -e "\033[10;25Hyou will exit this game, now"
        echo -e "\033[39;49m"
        sleep 1
        clear
        exit 1
        ;;
      *)
        draw_border
        echo -e "\033[22;2Hyour choice is wrong, please try again"
        sleep 1
        ;;
    esac
  done
}

function draw_border() {
  declare -i width
  declare -i high
  width=79
  high=23

  clear

  #Set the display color to white on black background.
  echo -e "\033[37;40m"
  #Set background color.
  for ((i = 1; i <= $width; i = i + 1)); do
    for ((j = 1; j <= $high; j = j + 1)); do
      #Set display position.
      echo -e "\033["$j";"$i"H "
    done
  done
  #Frame
  echo -e "\033[1;1H+\033["$high";1H+\033[1;"$width"H+\033["$high";"$width"H+"
  for ((i = 2; i <= $width - 1; i = i + 1)); do
    echo -e "\033[1;"$i"H-"
    echo -e "\033["$high";"$i"H-"
  done
  for ((i = 2; i <= $high - 1; i = i + 1)); do
    echo -e "\033["$i";1H|"
    echo -e "\033["$i";"$width"H|\n"
  done
}

function doexit() {
  draw_border
  echo -e "\033[10;30Hthis game will exit....."
  echo -e "\033[0m"
  sleep 2
  clear
  exit 1
}

#Clear the entire character drop area.
function clear_all_area() {
  local i j
  #Fill typing area.
  for ((i = 5; i <= 21; i++)); do
    for ((j = 3; j <= 77; j = j + 1)); do
      #Set display position.
      echo -e "\033[44m\033["$i";"$j"H "
    done
  done
  echo -e "\033[37;40m"
}

# Function:    Clear a list of character paths.
# Input parameter: The column number of the column to be cleared.
# Returned value:   Not have.
function clear_line() {
  local i
  #Fill typing area.
  for ((i = 5; i <= 21; i++)); do
    for ((j = $1; j <= $1 + 9; j = j + 1)); do
      echo -e "\033[44m\033["$i";"$j"H "
    done
  done
  echo -e "\033[37;40m"
}

# Function:    Characters do fall path moves.
# Input parameter: parameter1: Current line of character (depends on length of character interval timeout).
#                  parameter2: Character current column.
# Returned value:   Not have.
function move() {

  local locate_row lastloca
  locate_row=$(($1 + 5))
  #Displays the characters to be entered.
  echo -e "\033[30;44m\033["$locate_row";"$2"H$3\033[37;40m"
  if [ "$1" -gt "0" ]; then
    lastloca=$(($locate_row - 1))
    #Clear the previous position.
    echo -e "\033[30;44m\033["$lastloca";"$2"H \033[37;40m"
  fi
}

# Function:    The corresponding strings of different types are put into an array at a time for character conversion.
# Input parameter: The type of character to be stored in the array.
# Global variable: array[]
# Returned value:   Not have.
function putarray() {
  local chars
  case $1 in
    digit)
      chars='0123456789'
      for ((i = 0; i < 10; i++)); do
        array[$i]=${chars:$i:1}
      done
      ;;
    char)
      chars='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
      for ((i = 0; i < 52; i++)); do
        array[$i]=${chars:$i:1}
      done
      ;;
    mix)
      chars='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
      for ((i = 0; i < 62; i++)); do
        array[$i]=${chars:$i:1}
      done
      ;;
    *) ;;

  esac
}

# Function:    Generates a random number of the corresponding type, which is converted to the corresponding random character.
# Input parameter: Type of character to be generated.
# Global variable: random_char, array[]
# Returned value:   Not have.
function get_random_char() {
  local typenum
  declare -i typenum=0
  case $1 in
    digit)
      typenum=$(($RANDOM % 10))
      ;;
    char)
      typenum=$(($RANDOM % 52))
      ;;
    mix)
      typenum=$(($RANDOM % 62))
      ;;
    *) ;;

  esac
  random_char=${array[$typenum]}
}

function main() {
  declare -i gamestarttime=0
  declare -i gamedonetime=0

  declare -i starttime
  declare -i deadtime
  declare -i curtime
  declare -i donetime

  declare -i numright=0
  declare -i numtotal=0
  declare -i accuracy=0

  #Stores the corresponding character into the array,$1 is the type of punch character selected by the user.
  putarray $1

  # Initializes the game start time.
  gamestarttime=$(date +%s)

  while [ 1 ]; do
    echo -e "\033[2;2HPlease type the letters on the screen before the characters disappear!"

    echo -e "\033[3;2HPlaytime:     "
    curtime=$(date +%s)
    gamedonetime=$curtime-$gamestarttime
    echo -e "\033[31;40m\033[3;15H$gamedonetime s\033[37;40m"
    echo -e "\033[3;60HSum: \033[31;26m$numtotal\033[37;40m"
    echo -e "\033[3;30HAccuracy: \033[31;40m$accuracy %\033[37;40m"
    echo -ne "\033[22;2HYour input:                         "
    clear_all_area
    # Loop 10 times to check whether a column of characters timed out or was shot down.
    for ((line = 20; line <= 60; line = line + 10)); do
      #Check whether the column character is shot down.
      if [ "${ifchar[$line]}" == "" ] || [ "${donetime[$line]}" -gt "$time" ]; then
        # Clear the column display.
        clear_line $line
        #Reproduces a random character.
        if [ "$1" == "word" ]; then
          read -u 4 word
          if [ "$word" == "" ]; then # File read end.
            exec 4< $file
          fi
          putchar[$line]=$word
        else
          get_random_char $1
          putchar[$line]=$random_char
        fi
        numtotal=$numtotal+1
        # Flag bit, set 1.
        ifchar[$line]=1
        #Reset timer.
        starttime[$line]=$(date +%s)
        curtime[$line]=${starttime[$line]}
        donetime[$line]=$time
        #Reinitialize character position behavior 0.
        column[$line]=0
        if [ "$1" == "word" ]; then
          move 0 $line ${putchar[$line]}
        fi
      else
        #If there is no timeout or shot down, the timer and current position are updated.
        curtime[$line]=$(date +%s)
        donetime[$line]=${curtime[$line]}-${starttime[$line]}
        move ${donetime[$line]} $line ${putchar[$line]}
      fi
    done

    if [ "$1" != "word" ]; then
      echo -ne "\033[22;14H" # Clear the input line characters.
      # Check user input characters simultaneously as a one-second timer.
      if read -n 1 -t 0.5 tmp; then
        # Read in successfully, loop to check if the input matches a column.
        for ((line = 20; line <= 60; line = line + 10)); do
          if [ "$tmp" == "${putchar[$line]}" ]; then
            # Clear the column display.
            clear_line $line
            # If a match is found, the flag bit is cleared.
            ifchar[$line]=""
            echo -e "\007\033[32;40m\033[4;62H         right !\033[37;40m"
            numright=$numright+1
            # Exit a loop.
            break
          else
            # Otherwise, an error is always displayed until it times out.
            echo -e "\033[31;40m\033[4;62Hwrong,try again!\033[37;40m"
          fi
        done
      fi
    else
      echo -ne "\033[22;14H" # Clear the input line characters.
      # Check user input characters while acting as timers.
      if read tmp; then
        # Read in successfully, loop to check if the input matches a column.
        for ((line = 20; line <= 60; line = line + 10)); do
          if [ "$tmp" == "${putchar[$line]}" ]; then
            # Clear the column display.
            clear_line $line
            # If a match is found, the flag bit is cleared.
            ifchar[$line]=""
            echo -e "\007\033[32;40m\033[4;62H         right !\033[37;40m"
            numright=$numright+1
            # Exit a loop.
            break
          else
            # Otherwise, an error is always displayed until it times out.
            echo -e "\033[31;40m\033[4;62Hwrong,try again!\033[37;40m"
          fi
        done
      fi
    fi
    trap " doexit " 2 # Capture special signal.
    # Correct rate of calculation.
    accuracy=$numright*100/$numtotal
  done
}

#To define the typing timeout variable, the difficulty selection is both to set different typing timeout times.
declare -i time
function modechoose() {
  echo -e "\033[8;30H1) easy mode"
  echo -e "\033[9;30H2) normal mode"
  echo -e "\033[10;30H3) difficult mode"
  echo -ne "\033[22;2HPlease input your choice: "
  read mode
  case $mode in
    "1")
      time=10
      dismenu # Call the menu selection function.
      ;;
    "2")
      time=5
      dismenu
      ;;
    "3")
      time=3
      dismenu
      ;;
    *)
      echo -e "\033[22;2Hyour choice is wrong, please try again"
      sleep 1
      ;;
  esac
}

# -----------------------------------------------------------------
# Main program flow.

draw_border
dis_welcome
echo -ne "\033[3;30Hstart the game. Y/N : "
read yourchoice
if [ "$yourchoice" == "Y" ] || [ "$yourchoice" == "y" ]; then
  draw_border
  modechoose
else
  clear
  exit 1
fi

exit 1