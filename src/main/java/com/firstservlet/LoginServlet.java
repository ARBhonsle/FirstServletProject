package com.firstservlet;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@WebServlet(
        description = "Login Servlet Testing",
        urlPatterns = {"/LoginServlet"},
        initParams = {
                @WebInitParam(name = "userId", value = "Alexa"),
                @WebInitParam(name = "password", value = "ATest@123!"),
                @WebInitParam(name = "userId1", value = "evelyn"),
                @WebInitParam(name = "password1", value = "test"),
                @WebInitParam(name = "userId2", value = "ben"),
                @WebInitParam(name = "password2", value = "testing")
        }
)
public class LoginServlet extends HttpServlet {
    private static final String USERNAME_PATTERN = "[A-Z]{1}[a-zA-Z]{2,}";
    private static final Pattern userPattern = Pattern.compile(USERNAME_PATTERN);
    private static final String PASSWORD_PATTERN = "\\S*[A-Z]+\\S*[0-9]+\\S*[^a-zA-Z0-9\\s]{1}\\S*";
    private static final Pattern passwordPattern = Pattern.compile(PASSWORD_PATTERN);

    public boolean isUserNameValid(String user) {
        Matcher matcher = userPattern.matcher(user);
        return matcher.matches();
    }

    public boolean checkCredentials(String user, String userId, String pwd, String password) {
        return userId.equals(user) && password.equals(pwd);
    }

    public boolean isPasswordValid(String pwd) {
        if(!pwd.matches("\\S{8,}")){
            return false;
        }
        Matcher matcher = passwordPattern.matcher(pwd);
        return matcher.matches();
    }
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // get request parameters for UserID and Password
        String user = request.getParameter("user");
        String pwd = request.getParameter("pwd");
        // checking if valid user name
        if (!this.isUserNameValid(user)) {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();
            out.println("<font color = red>Invalid user name</font>");
            rd.include(request, response);
            return;
        }
        // checking if valid password
        if (!this.isPasswordValid(pwd)) {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();
            out.println("<font color = red>Invalid password</font>");
            rd.include(request, response);
            return;
        }
        // get servlet config init params
        String userId = getServletConfig().getInitParameter("userId");
        String password = getServletConfig().getInitParameter("password");
        if (this.checkCredentials(user, userId, pwd, password)) {
            request.setAttribute("user", user);
            request.getRequestDispatcher("LoginSuccess.jsp").forward(request, response);
        } else {
            RequestDispatcher rd = getServletContext().getRequestDispatcher("/login.html");
            PrintWriter out = response.getWriter();
            out.println("<font color =red>Either user name or password is wrong </font>");
            rd.include(request, response);
        }
    }

}
