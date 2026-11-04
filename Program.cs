using CbtisApp;
using System;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Db.Inicializar();

        // Cuentas de prueba (bórralas en producción).
        var auth = new AuthService();
        auth.Registrar("Profa. Demo", "profe1", "1234", Rol.Profesor);
        auth.Registrar("Alumno Demo", "20240001", "1234", Rol.Alumno);
        auth.Registrar("Tutor Demo", "tutor1", "1234", Rol.PadreTutor);

        Application.Run(new LoginForm());
    }
}