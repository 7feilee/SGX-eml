//
// http://csapp.cs.cmu.edu/3e/ics3/code/include/csapp.h
// http://csapp.cs.cmu.edu/3e/ics3/code/src/csapp.c
//

#ifndef SOCKET_RIO_HPP
#define SOCKET_RIO_HPP

#include <unistd.h>
#include <system_error>
#include <cstring>
#include <string>

/****************************************
 * The Rio package - Robust I/O functions
 ****************************************/

using namespace std;
#define RIO_BUFSIZE 4096

class RobustIO {
    int read_fd, write_fd;              /* Descriptor for this internal buf */
    int rio_cnt;                        /* Unread bytes in internal buf */
    size_t rio_buf_idx;                  /* Next unread byte in internal buf */
    char rio_buf[RIO_BUFSIZE];          /* Internal buffer */

    /*
    * rio_read - This is a wrapper for the Unix read() function that
    *    transfers min(n, rio_cnt) bytes from an internal buffer to a user
    *    buffer, where n is the number of bytes requested by the user and
    *    rio_cnt is the number of unread bytes in the internal buffer. On
    *    entry, rio_read() refills the internal buffer via a call to
    *    read() if the internal buffer is empty.
    */

    int rio_fill_buf() {
        /* Refill if buf is empty */
        while (rio_cnt <= 0) {
            rio_cnt = read(read_fd, rio_buf, sizeof(rio_buf));
            if (rio_cnt < 0 && errno != EINTR) {
                /* Interrupted by sig handler return */
                throw system_error(errno, generic_category(), __FUNCTION__);
            } else if (rio_cnt == 0) {
                /* EOF */
                return EOF;
            } else {
                /* Reset buffer ptr */
                rio_buf_idx = 0;
            }
        }

        return rio_cnt;
    }

    ssize_t rio_read(char *usr_buf, size_t n) {
        if (rio_cnt <= 0) {
            if (rio_fill_buf() == EOF) {
                return EOF;
            }
        }

        /* Copy min(n, rio_cnt) bytes from internal buf to user buf */
        int cnt = n;
        if (rio_cnt < n) {
            cnt = rio_cnt;
        }

        memcpy(usr_buf, rio_buf + rio_buf_idx, cnt);
        rio_buf_idx += cnt;
        rio_cnt -= cnt;
        return cnt;
    }


public:
    /* Associate a descriptor with a read buffer and reset buffer */
    explicit RobustIO(int fd) : read_fd(fd), write_fd(fd), rio_cnt(0), rio_buf_idx(0), rio_buf{0} {}

    RobustIO(int read_fd, int write_fd)
            : read_fd(read_fd), write_fd(write_fd), rio_cnt(0), rio_buf_idx(0), rio_buf{0} {}

    /*
     * rio_writen - Robustly write n bytes (unbuffered)
     */
    ssize_t write_n(void *usr_buf, size_t n) {
        char *buf_p = (char *) usr_buf;

        size_t n_left = n;
        while (n_left > 0) {
            ssize_t n_written = write(write_fd, buf_p, n_left);
            if (n_written <= 0 && errno != EINTR) {
                throw system_error(errno, generic_category(), __FUNCTION__);
            } else if (n_written > 0) {
                n_left -= n_written;
                buf_p += n_written;
            }
        }

        return n;
    }

    ssize_t writeline(const std::string &usr_buf) {
        ssize_t n_written = write_n((void *) usr_buf.c_str(), usr_buf.size());
        n_written += write_n((void *) "\n", 1);

        return n_written;
    }

    /*
     * rio_readn - Robustly read n bytes (unbuffered)
     */
    ssize_t read_n(void *usr_buf, size_t n) {
        char *buf_p = (char *) usr_buf;

        size_t n_left = n;
        while (n_left > 0) {
            ssize_t n_read = read(read_fd, buf_p, n_left);

            if (n_read < 0) {
                if (errno == EINTR) {   /* Interrupted by sig handler return and call read() again */
                    continue;
                } else {
                    throw system_error(errno, generic_category(), __FUNCTION__);
                }
            } else if (n_read == 0) {
                break;                  /* EOF */
            }

            n_left -= n_read;
            buf_p += n_read;
        }
        return (n - n_left);            /* Return >= 0 */
    }

    /*
     * rio_readnb - Robustly read n bytes (buffered)
     */
    ssize_t read_nb(void *usr_buf, size_t n) {
        char *buf_p = (char *) usr_buf;

        size_t n_left = n;
        while (n_left > 0) {
            ssize_t n_read = rio_read(buf_p, n_left);
            if (n_read == EOF) {
                break;                  /* EOF */
            }

            n_left -= n_read;
            buf_p += n_read;
        }
        return (n - n_left);            /* return >= 0 */
    }

    /*
     * rio_readlineb - Robustly read a text line (buffered)
     */
    ssize_t readline_b(void *usr_buf, size_t max_len) {
        char *buf_p = (char *) usr_buf;

        size_t n;
        char c;
        for (n = 1; n < max_len; n++) {
            if (rio_read(&c, 1) == EOF) {
                break;              /* EOF */
            }

            *buf_p++ = c;
            if (c == '\n') {
                n++;
                break;
            }
        }

        *buf_p = 0;
        return n - 1;
    }

    ssize_t readline_b(std::string &usr_buf) {
        char c;
        ssize_t cnt = 0;

        do {
            int rc = rio_read(&c, 1);

            if (rc == 1) {
                usr_buf.push_back(c);
                cnt++;
            } else if (rc == -1) {
                return EOF;
            }
        } while (c != '\n');

        return cnt;
    }

    ssize_t read_to_eof(std::string &usr_buf) {
        ssize_t cnt = 0;

        if (rio_cnt > 0) {
            usr_buf.insert(usr_buf.end(), rio_buf + rio_buf_idx, rio_buf + rio_buf_idx + rio_cnt);
            cnt += rio_cnt;
            rio_cnt = 0;
        }

        while (rio_fill_buf() != EOF) {
            usr_buf.insert(usr_buf.end(), rio_buf, rio_buf + rio_cnt);
            cnt += rio_cnt;
            rio_cnt = 0;
        }

        return cnt;
    }
};


#endif //SOCKET_RIO_HPP
