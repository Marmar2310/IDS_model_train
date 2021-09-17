import tkinter as tk
from tkinter import filedialog
from tkinter import *
import offline_predict as op
import ifcfg

window = tk.Tk(className="IDS")
window.geometry("450x250")
frame = tk.Frame(window)
frame.pack()

title = Label(text="ML-IDS",
              fg="light blue",
              bg="blue",
              font="Verdana 10 bold")
title.place(x=200, y=50)


def UploadAction():
    filename = filedialog.askopenfilename()
    print('Selected:', filename)
    with open(filename, "r+") as f:
        data = f.read().splitlines()
        print(data)
        offline_result = tk.Label(text=op.predictAttack(data))
        offline_result.pack()
        window.geometry("450x300")


def online_mode():
    lbl = tk.Label(text="online mode")
    lbl.pack()
    btn_online.destroy()
    btn_offline.destroy()
    title.destroy()
    options = [*ifcfg.interfaces().keys()]
    clicked = StringVar()
    clicked.set('Choose the wished interface')
    drop = OptionMenu(window, clicked, *options)
    drop.pack()

    def show():
        lbls.config(text=clicked.get())

    btn = Button(window, text="Enter", command=show)
    btn.pack()
    lbls = Label(window, text=" ")
    lbls.pack()


def offline_mode():
    lbl = tk.Label(text="offline mode")
    lbl.pack()
    btn_online.destroy()
    btn_offline.destroy()
    title.destroy()
    upload_btn = tk.Button(window, text='Open', command=UploadAction())
    upload_btn.place(x=175, y=225)


btn_online = tk.Button(text="ONLINE MODE",
                       fg='white', bg='black', command=online_mode)
btn_online.place(x=0, y=100)
# btn_online.pack()
btn_offline = tk.Button(text="OFFLINE MODE",
                        fg='white', bg='black', command=offline_mode)
btn_offline.place(x=325, y=100)
window.mainloop()
