import streamlit as st
from aes_2 import *
from blowfish import *
from rsa import *
from encryption_file import *
import matplotlib.pyplot as plt
from PIL import Image
from binascii import hexlify
from io import BytesIO

st.set_page_config(page_title="Hybrid Image Encryption and Decryption", page_icon="🔒")

st.title("Hybrid Image Encryption and Decryption")
option = st.sidebar.selectbox("Choose an option", ["Encrypt Image", "Decrypt Image"])

if option == "Encrypt Image":
    uploaded_file = st.file_uploader("Choose an image file", type=["jpg", "jpeg", "png"])
    if uploaded_file is not None:
        plaintext = uploaded_file.read()

        st.write("Length of Ciphertext:", len(plaintext))
        st.write("Input image graph")
        input_image = Image.open(uploaded_file)
        input_hist = input_image.histogram()
        fig, ax = plt.subplots()
        ax.set_title("Histogram of Input Image")
        ax.set_xlabel("Intensity Value")
        ax.set_ylabel("Frequency")
        ax.plot(input_hist)
        st.pyplot(fig)

        # Dictionary of Keys
        keys_iv = {}

        # Blowfish Layer 1
        blowfish_key = 'my 16bit Blowfish key'.encode()
        blowfish_cipher = Blowfish.new(blowfish_key, Blowfish.MODE_CBC)

        blowfish_ciphertext = blowfish_cipher.encrypt(pad(plaintext, Blowfish.block_size))

        keys_iv['blowfish_iv'] = hexlify(blowfish_cipher.iv)
        keys_iv['blowfish_key'] = hexlify(blowfish_key)

        # RSA Layer 2
        rsa_key = RSA.generate(2048)
        rsa_private_key = rsa_key
        rsa_public_key = rsa_key.publickey()

        cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
        rsa_plaintext = blowfish_ciphertext

        rsa_ciphertext = bytearray()
        for i in range(0, len(rsa_plaintext), 190):
            rsa_ciphertext.extend(cipher_rsa.encrypt(rsa_plaintext[i:i+190]))

        keys_iv['rsa_n'] = rsa_private_key.n
        keys_iv['rsa_e'] = rsa_private_key.e
        keys_iv['rsa_d'] = rsa_private_key.d

        # AES Layer 3
        aes_key = 'my 16bit AES key'.encode()
        aes_cipher = AES.new(aes_key, AES.MODE_CBC)
        aes_plaintext = rsa_ciphertext

        aes_ciphertext = aes_cipher.encrypt(pad(aes_plaintext, AES.block_size))

        ciphertext = aes_ciphertext

        keys_iv['aes_iv'] = hexlify(aes_cipher.iv)
        keys_iv['aes_key'] = hexlify(aes_key)

        st.write("Length of Ciphertext(HEX):", len(ciphertext.hex()))
        st.write("Length of Ciphertext:", len(ciphertext))
        st.write("Keys & IV:")
        st.write(keys_iv)

        output_image = Image.new("RGBA", input_image.size)
        output_image.putdata(list(zip(ciphertext)))
        output_hist = output_image.histogram()
        fig, ax = plt.subplots()
        ax.set_title("Histogram of Encrypted Image")
        ax.set_xlabel("Intensity Value")
        ax.set_ylabel("Frequency")
        ax.plot(output_hist)
        st.pyplot(fig)
        
        with open("encrypted_image2.png", "wb") as f:
            f.write(output_image.tobytes())
        
        st.download_button(
            label="Download Encrypted Image",
            data=output_image.tobytes(),
            file_name="encrypted_image2.png",
            mime="image/png",
        )
if option == "Decrypt Image":
    # Get file from user
    uploaded_file = st.file_uploader("Choose a file")
    if uploaded_file is not None:
        # Read image file
        img = Image.open(uploaded_file)
        # Display original image

        # Convert image to byte array
        plaintext = bytearray(img.tobytes())

        # Decrypt image using AES, RSA, and Blowfish
        decryption_key_aes = unhexlify(keys_iv['aes_key'])
        decryption_iv_aes = unhexlify(keys_iv['aes_iv'])
        decryption_key_rsa = RSA.construct(rsa_components=(keys_iv['rsa_n'], keys_iv['rsa_e'], keys_iv['rsa_d']))
        decryption_iv_blowfish = unhexlify(keys_iv['blowfish_iv'])
        decryption_key_blowfish = unhexlify(keys_iv['blowfish_key'])

        aes_cipher_decryption = AES.new(decryption_key_aes, AES.MODE_CBC, iv=decryption_iv_aes)
        rsa_cipher_decryption = PKCS1_OAEP.new(decryption_key_rsa)
        blowfish_cipher_decryption = Blowfish.new(decryption_key_blowfish, Blowfish.MODE_CBC, iv=decryption_iv_blowfish)

        # AES DECRYPTION
        ciphertext_rsa = unpad(aes_cipher_decryption.decrypt(ciphertext), AES.block_size)
        # RSA DECRYPTION
        ciphertext_blowfish = bytearray()
        for i in range(0, len(ciphertext_rsa), 256):
            ciphertext_rsa_segment = ciphertext_rsa[i:i + 256]
            ciphertext_blowfish.extend(rsa_cipher_decryption.decrypt(ciphertext_rsa_segment))

        # BLOWFISH DECRYPTION
        decrypted_plaintext = unpad(blowfish_cipher_decryption.decrypt(ciphertext_blowfish), Blowfish.block_size)

        # Save decrypted image to file
        with open("decrypted_image2.png", "wb") as f:
            f.write(decrypted_plaintext)

        # Display decrypted image
        img_decrypted = Image.open("decrypted_image2.png")

        # Display histogram of decrypted image
        decrypt_hist = img_decrypted.histogram()
        fig, ax = plt.subplots()
        ax.plot(decrypt_hist)
        ax.set_title("Histogram of Decrypted Image")
        ax.set_xlabel("Intensity Value")
        ax.set_ylabel("Frequency")
        st.pyplot(fig)
        
        # Create a download link for the decrypted image
        with BytesIO() as f:
            img_decrypted.save(f, format="PNG")
            st.download_button(
                label="Download Decrypted Image",
                data=f.getvalue(),
                file_name="decrypted_image2.png",
                mime="image/png"
            )







        
        
        
        

