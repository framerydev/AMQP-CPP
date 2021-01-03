/**
 *  The login information to access a server
 *
 *  This class combines login, password and vhost
 *
 *  @copyright 2014 - 2018 Copernica BV
 */

/**
 *  Include guard
 */
#pragma once

/**
 *  Dependencies
 */
#include <string>

/**
 *  Set up namespace
 */
namespace AMQP
{

    typedef enum
    {
        LOGIN_PLAIN,
        LOGIN_EXTERNAL
    } LoginMechanism;

    /**
 *  Class definition
 */
    class Login
    {
    private:
        /**
     *  The username
     *  @var string
     */
        std::string _user;

        /**
     *  The password
     *  @var string
     */
        std::string _password;

        /**
    *  The login mechanism
    *  @var LoginMechanism
    */
        LoginMechanism _mechanism;

    public:
        /**
     *  Default constructor
     */
        Login() : _mechanism(LOGIN_PLAIN), _user("guest"), _password("guest") {}

        /**
     *  Constructor
     *  @param  user
     *  @param  password
     */
        Login(std::string user, std::string password) : _mechanism(LOGIN_PLAIN), _user(std::move(user)), _password(std::move(password)) {}

        /**
     *  Constructor
     *  @param  user
     *  @param  password
     */
        Login(const char *user, const char *password) : _mechanism(LOGIN_PLAIN), _user(user), _password(password) {}

        /**
     *  Constructor
     *  @param  LoginMechanism
     */
        Login(LoginMechanism mechanism) : _mechanism(mechanism), _user("guest"), _password("guest") {}

        /**
     *  Destructor
     */
        virtual ~Login() = default;

        /**
     *  Cast to boolean: is the login set?
     *  @return bool
     */
        operator bool() const
        {
            return !_user.empty() || !_password.empty();
        }

        /**
     *  Negate operator: is it not set
     *  @return bool
     */
        bool operator!() const
        {
            return _user.empty() && _password.empty();
        }

        /**
     *  Retrieve the user name
     *  @return string
     */
        const std::string &user() const
        {
            return _user;
        }

        /**
     *  Retrieve the password
     *  @return string
     */
        const std::string &password() const
        {
            return _password;
        }

        /**
     *  Retrieve login mechanism string representation
     *  @return LoginMechanism
     */
        std::string mechanismRepr() const
        {
            switch (_mechanism)
            {
            case LOGIN_PLAIN:
                return "PLAIN";
            case LOGIN_EXTERNAL:
                return "EXTERNAL";
            default:
                return "";
            }
        }

        std::string stringRepr() const
        {
            // we need an initial string
            std::string result("\0", 1);

            // append other elements
            return result.append(_user).append("\0", 1).append(_password);
            if (_mechanism == LOGIN_PLAIN)
            {
                // append login and password info for plain login
                return result.append(_user).append("\0", 1).append(_password);
            }
            return result;
        }

        /**
     *  String representation in SASL PLAIN mode
     *  @return string
     */
        std::string saslPlain() const
        {
            // we need an initial string
            std::string result("\0", 1);

            // append other elements
            return result.append(_user).append("\0", 1).append(_password);
        }

        /**
     *  Comparison operator
     *  @param  that
     *  @return bool
     */
        bool operator==(const Login &that) const
        {
            // username and password must match
            return _user == that._user && _password == that._password;
        }

        /**
     *  Comparison operator
     *  @param  that
     *  @return bool
     */
        bool operator!=(const Login &that) const
        {
            // the opposite of operator==
            return !operator==(that);
        }

        /**
     *  Comparison operator
     *  @param  that
     *  @return bool
     */
        bool operator<(const Login &that) const
        {
            // compare users
            if (_user != that._user)
                return _user < that._user;

            // compare passwords
            return _password < that._password;
        }

        /**
     *  Friend function to allow writing the login to a stream
     *  @param  stream
     *  @param  login
     *  @return std::ostream
     */
        friend std::ostream &operator<<(std::ostream &stream, const Login &login)
        {
            // write username and password
            return stream << login._user << ":" << login._password;
        }
    };

    /**
 *  End of namespace
 */
} // namespace AMQP
