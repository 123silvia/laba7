using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace WindowsFormsApp1
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            textBox3.ReadOnly = true;
            textBox4.ReadOnly = true;
        }
        private ECDsaCng CreateECDKey (out byte[] PrivateKey, out byte[] PublicKey, string KeyName, string keyAlias)
        { 
            //генерируем точку (ключ) P
            var p = new CngKeyCreationParameters
            {
                //задаем политику экспорта (может экспортироваться несколько раз)
                ExportPolicy = CngExportPolicies.AllowPlaintextExport,
                //параметры (может перезаписываться)
                KeyCreationOptions = CngKeyCreationOptions.OverwriteExistingKey,
                //пользовательский интерфейс (уровень защиты секретный ключ, имя ключа)
                UIPolicy = new CngUIPolicy(CngUIProtectionLevels.ProtectKey, KeyName, null, null, null)
            };
            //создаем ключ (Алгоритм, в котором будет использоваться ключ; имя ключа и p) 
            var key = CngKey.Create(CngAlgorithm.ECDsaP521, keyAlias, p);
            using (ECDsaCng dsa=new ECDsaCng(key))
            {   
                //используем алгоритм хэша Sha512
                dsa.HashAlgorithm = CngAlgorithm.Sha512;
                //получаем открытые и закрытые ключи 
                PublicKey = dsa.Key.Export(CngKeyBlobFormat.EccPublicBlob);
                PrivateKey = dsa.Key.Export(CngKeyBlobFormat.EccPrivateBlob);
                return dsa;
            }
        }
        private void Form1_Load(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (textBox1.Text != "" && textBox2.Text != "")
            {
                string KeyName = textBox1.Text;
                string keyAlias = textBox2.Text;
                byte[] private_key;
                byte[] public_key;
                var dsa = CreateECDKey(out private_key, out public_key, KeyName, keyAlias);
                var public_key1= BitConverter.ToString(public_key, 0);
                public_key1 = public_key1.Replace("-", string.Empty);
                textBox3.Text = public_key1;
                var private_key1=BitConverter.ToString(private_key, 0);
                private_key1 = private_key1.Replace("-", string.Empty);
                textBox4.Text = private_key1;
            }
            else
                MessageBox.Show("Поля не должны быть пустыми!", "Ошибка", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
