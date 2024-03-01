from tkinter import *
import hashlib
import os
import re
import datetime
from tkinter import messagebox

myGui = Tk()

myGui.geometry('680x350')
myGui.title('Password Authentication')
guiFont = font = dict(family='Bahnscharift', size=18, color='#7f7f7f')

#====== Password Entry ==========
eLabel = Label(myGui, text="Please Enter Username:   ", font=guiFont)
eLabel.grid(row=0, column=0)

eUsername = Entry(myGui, width=65)
eUsername.grid(row=0, column=1)

eLabel = Label(myGui, text="Please Enter Password:   ", font=guiFont)
eLabel.grid(row=1, column=0)

ePassword = Entry(myGui, show="*", width=65)
ePassword.grid(row=1, column=1)

lblVerify = Label(myGui, text="Authentication of password:   ", font=guiFont)
lblVerify.grid(row=5, column=0, pady=10)

entryVerify = Entry(myGui, show="*",width= 65)
entryVerify.grid(row=5, column=1)

#====== Strength Check =======

def checkPassword():
    strength = ['Password can not be Blank', 'Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']
    score = 1
    password = ePassword.get()
    print (password) ; len(password)

    if len(password) == 0:
        passwordStrength.set(strength[0])
        return

    if len(password) < 4:
        passwordStrength.set(strength[1])
        return

    if len(password) >= 8:
        score += 1

    if re.search("[0-9]", password):
        score += 1

    if re.search("[a-z]", password) and re.search("[A-Z]", password):
        score += 1

    if re.search(".", password):
        score += 1

    passwordStrength.set(strength[score])

passwordStrength = StringVar()
checkStrBtn = Button(myGui, text="Check Strength", command=checkPassword, height=1, width=20, font=guiFont)
checkStrBtn.grid(row=2, column=0,pady=10)

checkStrLab = Label(myGui, textvariable=passwordStrength)
checkStrLab.grid(row=2, column=1, sticky=W)
 
#====== Hash the Password ======

def passwordHash():
    if len(ePassword.get()) !=0:
        hash_obj1 = hashlib.sha256()
        pwsha256 = ePassword.get().encode('utf-8')
        hash_obj1.update(pwsha256)
        sha256pw.set(hash_obj1.hexdigest())
    
    password = ePassword.get()
    print (password) ; len(password)
    if len(password) == 0:
        checkPassword();
    return

sha256pw = StringVar()
hashBtn = Button(myGui, text="Generate Hash Code", command=passwordHash, height=1, width=20, font=guiFont)
hashBtn.grid(row=3, column=0, pady=10)

hashLbl = Label(myGui, textvariable=sha256pw)
hashLbl.grid(row=3, column=1, sticky=W)

#====== Log the Hash to a file =======

def hashlog():
    loghash = sha256pw.get()
    filepath = 'C:\\Users\\ravik\\OneDrive\\Desktop\\My Documents\\J-Component\\NIS\\password_hash_file.txt'
    os.path.isfile(filepath)
    obj1 = open(filepath, 'a')
    obj1.write(f"{datetime.datetime.now()} - Username: {eUsername.get()}, Hash code: {sha256pw.get()}, Strength: {passwordStrength.get()}\n")
    obj1.write("\n")
    
    loglbl = Label(myGui, text="")
    loglbl.config(text="Hash Logged.!")
    loglbl.grid(row=7, column=1, sticky=W)

btnLog = Button(myGui, text="Log Hash", command=hashlog, height=1, width=20, font=guiFont)
btnLog.grid(row=7, column=0, pady=10)



#====== Re enter password and check against stored hash ======

def verify():
    password1 = ePassword.get()
    password2 = entryVerify.get()
    check = ['Authentication failed.!','Authentication Successful.!']
    l1=len(ePassword.get())
    l2=len(entryVerify.get())
    if (l1 == 0 and l2 == 0):
        checkPassword()
        return
    if (l1 == 0 and l2 != 0):
        checkPassword()
        return
    if password1 == password2:
        i=1
        verified.set(check[i])
    else:
        i=0
        verified.set(check[i])
    
verified = StringVar()
btnVerify = Button(myGui, text="Authentication", command=verify, height=1, width=20, font=guiFont)
btnVerify.grid(row=6, column=0)

checklbl = Label(myGui, textvariable=verified)
checklbl.grid(row=6, column=1, sticky=W)

myGui.mainloop()