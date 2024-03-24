import logic
import tkinter as tk
import subprocess
import os
from PIL import ImageTk, Image
import tkinter.messagebox as mb


def open_file(filename):
    try:
        current_directory = os.getcwd()
        # Формируем путь к файлу "TestFile.txt" в текущей директории
        source_path = os.path.join(current_directory, filename)

        subprocess.Popen(["start", "notepad", source_path], shell=True)
    except Exception as e:
        mb.showerror("Ошибка", f"Невозможно открыть файл: {e}")


def print_result_in_file(message, filename):
    output = open(filename, "w+")
    output.write(message.hex())
    output.close()


def define_sim_crypt_button():
    file = open("input.txt", "rb")
    message = file.read()
    file.close()
    print(message)

    result = logic.simetric_crypt(message)
    print_result_in_file(result, "ResSim.txt")


def define_asim_crypt_button():
    file = open("input.txt", "rb")
    message = file.read()
    file.close()

    result = logic.asimetric_crypt(message)
    print_result_in_file(result, "ResAsim.txt")


def define_digital_signature_button():
    file = open("input.txt", "rb")
    message = file.read()
    file.close()

    result = logic.digital_signature(message)
    print_result_in_file(result, "ResSignature.txt")


def define_hash_button():
    file = open("input.txt", "rb")
    message = file.read()
    file.close()

    result = logic.hashing(message)
    print_result_in_file(result, "ResHash.txt")


def initialization():
    root = tk.Tk()
    root.title("cryptography")
    img = Image.open("bg9try.jpg")
    width = 500
    ratio = (width / float(img.size[0]))
    height = int((float(img.size[1]) * float(ratio))) + 20
    imag = img.resize((width, height), Image.LANCZOS)
    image = ImageTk.PhotoImage(imag)
    tk.Label(root, image=image).pack(side="top", fill="both", expand="no")

    tk.Button(root, text="Симетричное\nшифрование", command=lambda: define_sim_crypt_button(),
              activebackground="black").place(x=75, y=30)
    tk.Button(root, text="Асимитричное\nшифрование", command=lambda: define_asim_crypt_button(),
              activebackground="black").place(x=75, y=100)
    tk.Button(root, text="Цифровая\nподпись", command=lambda: define_digital_signature_button(),
              activebackground="black").place(x=75, y=170)
    tk.Button(root, text="Выполнить\nхеширование", command=lambda: define_hash_button(),
              activebackground="black").place(x=75, y=240)
    tk.Button(root, text="Изменить\nвходное сообщение", command=lambda: open_file("input.txt"),
              activebackground="black").place(x=255, y=10)
    tk.Button(root, text="Посмотреть\nрез. сим. шифрования", command=lambda: open_file("ResSim.txt"),
              activebackground="black").place(x=255, y=70)
    tk.Button(root, text="Посмотреть\nрез. асим. шифрования", command=lambda: open_file("ResAsim.txt"),
              activebackground="black").place(x=255, y=130)
    tk.Button(root, text="Посмотреть\nрезультат хеширования", command=lambda: open_file("ResSignature.txt"),
              activebackground="black").place(x=255, y=190)
    tk.Button(root, text="Посмотреть\nрезультат хеширования", command=lambda: open_file("ResHash.txt"),
              activebackground="black").place(x=255, y=250)
    root.mainloop()


def begin():
    initialization()
