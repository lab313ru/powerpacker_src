import os
import subprocess
import filecmp


def test1(path):
    path1 = os.path.join('../', 'UNPACKED', path)

    if not os.path.exists(path1):
        return

    add = ''

    while True:
        path2 = os.path.join('../', 'UNPACKED', '2_%s' % path)
        path3 = os.path.join('../', 'PACKED', path)

        subprocess.run(['powerpack.exe',
                        path1,
                        path2,
                        '-c',
                        '-e=5',
                        add])

        if not filecmp.cmp(path2, path3):
            os.remove(path2)

            if add != '':
                print('Bad compression: %s' % path1)
                break

            add = '-o'
            continue
        else:
            os.remove(path2)
            print('OK: %s' % path1)
            break


def test2(path):
    path1 = os.path.join('../', 'PACKED', path)

    if not os.path.exists(path1):
        return

    path2 = os.path.join('../', 'UNPACKED', '2_%s' % path)
    path3 = os.path.join('../', 'UNPACKED', path)

    subprocess.run(['powerpack.exe',
                    path1,
                    path2,
                    '-d'])

    if not filecmp.cmp(path2, path3):
        print('Bad decompression: %s' % path1)
    else:
        print('OK: %s' % path1)

    os.remove(path2)


def test3(path, passwd):
    path1 = os.path.join('../', 'UNPACKED', path)

    if not os.path.exists(path1):
        return

    path2 = os.path.join('../', 'PACKED', '2_%s' % path)
    path3 = os.path.join('../', 'UNPACKED', '3_%s' % path)

    subprocess.run(['powerpack.exe',
                    path1,
                    path2,
                    '-c',
                    '-e=5',
                    '-p=%s' % passwd])

    subprocess.run(['powerpack.exe',
                    path2,
                    path3,
                    '-d',
                    '-p=%s' % passwd])

    if not filecmp.cmp(path1, path3):
        print('Bad compression with passwd: %s' % path1)
    else:
        print('OK: %s' % path1)

    os.remove(path2)
    os.remove(path3)


if __name__ == '__main__':
    with open('list.txt') as f:
        for fname in f.readlines():
            fname = fname.rstrip()
            test1(fname)
            test2(fname)
            test3(fname, 'testpass')
