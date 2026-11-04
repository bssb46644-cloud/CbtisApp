// =====================================================================
// CbtisApp - Estructura inicial (Windows Forms, .NET Framework 4.7.2, SQLite)
// Paquete NuGet requerido: Microsoft.Data.Sqlite
// =====================================================================
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Windows.Forms;
using Microsoft.Data.Sqlite;

namespace CbtisApp
{
    #region Models

    /// <summary>Roles del sistema.</summary>
    public enum Rol { Profesor = 1, Alumno = 2, PadreTutor = 3 }

    /// <summary>Clase base de todos los usuarios.</summary>
    public abstract class Usuario
    {
        public int Id { get; set; }
        public string Nombre { get; set; } = "";
        public string Login { get; set; } = "";   // matrícula, CURP, correo, etc.
        public Rol Rol { get; protected set; }
        public string PasswordHash { get; set; } = ""; // NUNCA guardar la contraseña en texto plano
    }

    public class Profesor : Usuario
    {
        public string Especialidad { get; set; } = "";
        public Profesor() { Rol = Rol.Profesor; }
    }

    public class Alumno : Usuario
    {
        public string Grupo { get; set; } = "";     // Ej. "3° B Programación"
        public string Matricula { get; set; } = "";
        public Alumno() { Rol = Rol.Alumno; }
    }

    public class PadreTutor : Usuario
    {
        public List<int> AlumnosIds { get; set; } = new(); // hijos vinculados
        public PadreTutor() { Rol = Rol.PadreTutor; }
    }

    /// <summary>Comunicado del profesor a un grupo.</summary>
    public class Aviso
    {
        public int Id { get; set; }
        public int ProfesorId { get; set; }
        public string Grupo { get; set; } = "";
        public string Titulo { get; set; } = "";
        public string Mensaje { get; set; } = "";
        public DateTime Fecha { get; set; } = DateTime.Now;
    }

    /// <summary>Nota de un alumno por materia y parcial.</summary>
    public class Calificacion
    {
        public int Id { get; set; }
        public int AlumnoId { get; set; }
        public string Materia { get; set; } = "";
        public int Parcial { get; set; }          // 1, 2, 3
        public decimal Nota { get; set; }         // 0 - 10
    }

    public enum EstadoAsistencia { Asistencia, Falta, Retardo, Justificada }

    /// <summary>Registro diario de asistencia.</summary>
    public class Asistencia
    {
        public int Id { get; set; }
        public int AlumnoId { get; set; }
        public string Materia { get; set; } = "";
        public DateTime Fecha { get; set; } = DateTime.Today;
        public EstadoAsistencia Estado { get; set; }
    }

    public enum TipoReporte { Conducta, Incidencia, Felicitacion }

    /// <summary>Reporte de conducta/incidencia visible para el padre/tutor.</summary>
    public class Reporte
    {
        public int Id { get; set; }
        public int AlumnoId { get; set; }
        public int ProfesorId { get; set; }
        public TipoReporte Tipo { get; set; }
        public string Descripcion { get; set; } = "";
        public DateTime Fecha { get; set; } = DateTime.Now;
    }

    #endregion

    #region Data

    /// <summary>Acceso a SQLite: crea la BD y las tablas la primera vez.</summary>
    public static class Db
    {
        private const string ConnStr = "Data Source=cbtis.db";

        public static SqliteConnection Abrir()
        {
            var cn = new SqliteConnection(ConnStr);
            cn.Open();
            return cn;
        }

        public static void Inicializar()
        {
            using var cn = Abrir();
            using var cmd = cn.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS Usuarios (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Nombre TEXT NOT NULL,
                    Login TEXT NOT NULL,
                    Rol INTEGER NOT NULL,
                    PasswordHash TEXT NOT NULL,
                    UNIQUE (Login, Rol)
                );
                CREATE TABLE IF NOT EXISTS Tutorias (   -- vincula padre/tutor con alumno
                    PadreId INTEGER NOT NULL,
                    AlumnoId INTEGER NOT NULL,
                    PRIMARY KEY (PadreId, AlumnoId)
                );
                CREATE TABLE IF NOT EXISTS Avisos (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ProfesorId INTEGER, Grupo TEXT, Titulo TEXT, Mensaje TEXT, Fecha TEXT
                );
                CREATE TABLE IF NOT EXISTS Calificaciones (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    AlumnoId INTEGER, Materia TEXT, Parcial INTEGER, Nota REAL
                );
                CREATE TABLE IF NOT EXISTS Asistencias (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    AlumnoId INTEGER, Materia TEXT, Fecha TEXT, Estado INTEGER
                );
                CREATE TABLE IF NOT EXISTS Reportes (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    AlumnoId INTEGER, ProfesorId INTEGER, Tipo INTEGER, Descripcion TEXT, Fecha TEXT
                );";
            cmd.ExecuteNonQuery();
        }
    }

    #endregion

    #region Services

    /// <summary>Hash de contraseñas con PBKDF2 (salt aleatorio por usuario).</summary>
    public static class PasswordHasher
    {
        public static string Hash(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
        }

        public static bool Verificar(string password, string almacenado)
        {
            var partes = almacenado.Split('.');
            if (partes.Length != 2) return false;
            byte[] salt = Convert.FromBase64String(partes[0]);
            byte[] esperado = Convert.FromBase64String(partes[1]);
            byte[] actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, 100_000, HashAlgorithmName.SHA256, 32);
            return CryptographicOperations.FixedTimeEquals(actual, esperado);
        }
    }

    /// <summary>Usuario que inició sesión (disponible en toda la app).</summary>
    public static class Sesion
    {
        public static Usuario? Actual { get; set; }
    }

    /// <summary>Lógica de autenticación según el rol seleccionado.</summary>
    public class AuthService
    {
        /// <returns>El usuario autenticado o null si las credenciales son inválidas.</returns>
        public Usuario? Autenticar(string login, string password, Rol rol)
        {
            using var cn = Db.Abrir();
            using var cmd = cn.CreateCommand();
            // Consulta parametrizada: evita inyección SQL.
            cmd.CommandText = "SELECT Id, Nombre, PasswordHash FROM Usuarios WHERE Login = $l AND Rol = $r";
            cmd.Parameters.AddWithValue("$l", login.Trim());
            cmd.Parameters.AddWithValue("$r", (int)rol);

            using var rd = cmd.ExecuteReader();
            if (!rd.Read()) return null;

            if (!PasswordHasher.Verificar(password, rd.GetString(2))) return null;

            // Se crea la subclase correcta según el rol.
            Usuario u = rol switch
            {
                Rol.Profesor => new Profesor(),
                Rol.Alumno => new Alumno(),
                _ => new PadreTutor()
            };
            u.Id = rd.GetInt32(0);
            u.Nombre = rd.GetString(1);
            u.Login = login.Trim();
            return u;
        }

        /// <summary>Registro de usuario nuevo (úsalo para crear cuentas de prueba).</summary>
        public bool Registrar(string nombre, string login, string password, Rol rol)
        {
            try
            {
                using var cn = Db.Abrir();
                using var cmd = cn.CreateCommand();
                cmd.CommandText = "INSERT INTO Usuarios (Nombre, Login, Rol, PasswordHash) VALUES ($n,$l,$r,$p)";
                cmd.Parameters.AddWithValue("$n", nombre);
                cmd.Parameters.AddWithValue("$l", login.Trim());
                cmd.Parameters.AddWithValue("$r", (int)rol);
                cmd.Parameters.AddWithValue("$p", PasswordHasher.Hash(password));
                cmd.ExecuteNonQuery();
                return true;
            }
            catch (SqliteException) { return false; } // login duplicado para ese rol
        }
    }

    #endregion

    #region Forms

    /// <summary>Paleta institucional.</summary>
    public static class Tema
    {
        public static readonly Color Vino = ColorTranslator.FromHtml("#722F37");
        public static readonly Color RojoClaro = ColorTranslator.FromHtml("#F4C7C3");
        public static readonly Color Blanco = Color.White;
    }

    /// <summary>Pantalla de inicio de sesión (sin diseñador, todo por código).</summary>
    public class LoginForm : Form
    {
        private readonly ComboBox cmbRol = new() { DropDownStyle = ComboBoxStyle.DropDownList };
        private readonly TextBox txtUsuario = new() { PlaceholderText = "Matrícula / usuario" };
        private readonly TextBox txtPassword = new() { PlaceholderText = "Contraseña", UseSystemPasswordChar = true };
        private readonly Button btnEntrar = new() { Text = "Iniciar sesión" };
        private readonly Label lblError = new() { ForeColor = Color.Firebrick, AutoSize = true };
        private readonly AuthService _auth = new();

        public LoginForm()
        {
            Text = "CBTis - Seguimiento escolar";
            Size = new Size(420, 460);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            BackColor = Tema.RojoClaro;

            // Encabezado vino
            var header = new Label
            {
                Text = "CBTis\nSeguimiento escolar",
                Dock = DockStyle.Top,
                Height = 100,
                BackColor = Tema.Vino,
                ForeColor = Tema.Blanco,
                Font = new Font("Segoe UI", 16, FontStyle.Bold),
                TextAlign = ContentAlignment.MiddleCenter
            };

            // Tarjeta blanca
            var card = new Panel { BackColor = Tema.Blanco, Location = new Point(30, 125), Size = new Size(345, 270) };

            cmbRol.DataSource = Enum.GetValues(typeof(Rol));
            cmbRol.SetBounds(25, 25, 295, 30);
            txtUsuario.SetBounds(25, 70, 295, 30);
            txtPassword.SetBounds(25, 115, 295, 30);
            lblError.Location = new Point(25, 155);

            btnEntrar.SetBounds(25, 190, 295, 40);
            btnEntrar.BackColor = Tema.Vino;
            btnEntrar.ForeColor = Tema.Blanco;
            btnEntrar.FlatStyle = FlatStyle.Flat;
            btnEntrar.FlatAppearance.BorderSize = 0;
            btnEntrar.Click += BtnEntrar_Click;
            AcceptButton = btnEntrar; // Enter = iniciar sesión

            card.Controls.AddRange(new Control[] { cmbRol, txtUsuario, txtPassword, lblError, btnEntrar });
            Controls.Add(card);
            Controls.Add(header);
        }

        private void BtnEntrar_Click(object? sender, EventArgs e)
        {
            lblError.Text = "";
            if (string.IsNullOrWhiteSpace(txtUsuario.Text) || string.IsNullOrEmpty(txtPassword.Text))
            {
                lblError.Text = "Completa usuario y contraseña.";
                return;
            }

            var rol = (Rol)cmbRol.SelectedItem!;
            var usuario = _auth.Autenticar(txtUsuario.Text, txtPassword.Text, rol);
            if (usuario == null)
            {
                lblError.Text = "Credenciales incorrectas para ese rol.";
                return;
            }

            Sesion.Actual = usuario;
            Hide();

            // Redirige al dashboard según el rol.
            Form dashboard = usuario.Rol switch
            {
                Rol.Profesor => new DashboardProfesorForm(),
                Rol.Alumno => new DashboardAlumnoForm(),
                _ => new DashboardPadreForm()
            };
            dashboard.FormClosed += (_, _) => Close();
            dashboard.Show();
        }
    }

    // Marcadores de posición: aquí irán los módulos de cada rol.
    public class DashboardProfesorForm : Form
    { public DashboardProfesorForm() { Text = "Profesor: avisos, asistencia, calificaciones, reportes"; WindowState = FormWindowState.Maximized; } }
    public class DashboardAlumnoForm : Form
    { public DashboardAlumnoForm() { Text = "Alumno: horario, avisos, calificaciones"; WindowState = FormWindowState.Maximized; } }
    public class DashboardPadreForm : Form
    { public DashboardPadreForm() { Text = "Padre/Tutor: reportes, avisos, asistencias"; WindowState = FormWindowState.Maximized; } }

    #endregion

    #region Program

    

    #endregion
}