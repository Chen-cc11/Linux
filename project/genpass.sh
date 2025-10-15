#!/bin/bash

#Random Password Generator
#This script generates a random password that meets the specified requirements.
generate_password() {
  local length=12
  local password=''

  local special_chars='><+-{}:.&;'
  local special_char="${special_chars:$RANDOM%${#special_chars}:1}"
  password+="$special_char"

  local digits='0123456789'
  local digit="${digits:$RANDOM%${#digits}:1}"
  password+="$digit"

  local upper_case='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  local upper="${upper_case:$RANDOM%${#upper_case}:1}"
  password+="$upper"

  local lower_case='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  local lower="${lower_case:$RANDOM%${#lower_case}:1}"
  password+="$lower"

  local remaining_length=$((length-4))
  local characters='><+-{}:.&;0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
  local num_characters=${#characters}

  for ((i = 0; i < remaining_length; i++)); do
    local random_char="${characters:$RANDOM%$num_characters:1}"
    password+="$random_char"
  done

  #Shuffle the order of password characters
  password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')

  echo "$password"
}

generate_password