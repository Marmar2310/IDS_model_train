import tkinter as tk
from tkinter import filedialog

window = tk.Tk()
window.geometry("450x350")
frame = tk.Frame(window)
frame.pack()

def UploadAction():
    filename = filedialog.askopenfilename()
    print('Selected:', filename)

def online_mode():
    lbl = tk.Label(text="online mode")
    lbl.pack()
    btn_online.destroy()
    btn_offline.destroy()

def offline_mode():
    lbl = tk.Label(text="offline mode")
    lbl.pack()
    btn_online.destroy()
    btn_offline.destroy()
    upload_btn = tk.Button(window, text='Open', command=UploadAction())
    upload_btn.place(x=175,y=225)
btn_online = tk.Button(text="ONLINE MODE",
                       fg='white', bg='black', command=online_mode)
btn_online.place(x=0,y=100)
# btn_online.pack()
btn_offline = tk.Button(text="OFFLINE MODE",
                       fg='white', bg='black', command=offline_mode)
btn_offline.place(x=350,y=100)
window.mainloop()

