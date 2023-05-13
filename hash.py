# btw... is free just use it
# created by github.com/fooster1337

from colorama import Fore, init
from concurrent.futures import ProcessPoolExecutor
import hashlib
import argparse
import sys
init(autoreset=True)
red = Fore.RED
green = Fore.GREEN
reset = Fore.RESET

version = 1.0
#thread = 0
wordlist = []
success = 0
failed = 0

def error_msg(msg: str):
    print(f'{red}Error: {reset}{msg}')
    #parser.print_help()
    sys.exit(0)

def crack(type, target, wordlist, output):
    try:
    #print(target)
    #global wordlist
        global success, failed
        if type == "md5":
            for tar in target:
        #targetmd5 = hashlib.md5(target.encode('utf-8')).hexdigest()
                for pw in wordlist:
                    pwmd5 = hashlib.md5(pw.encode('utf-8')).hexdigest()
                    if tar == pwmd5:
                        success += 1
                        print(f"{green}Found{reset} : {tar}:{pw}")
                        open(output, 'a+', encoding='utf-8').write(f'{tar}:{pw}'+'\n')
                    else:
                        failed += 1
                        print(f"{red}Not Match{reset} : {tar}:{pw}")

        elif type == "sha256":
            for tar in target:
                for pw in wordlist:
                    pwsha256 = hashlib.sha256(pw.encode('utf8')).hexdigest()
                    if tar == pwsha256:
                        success += 1
                        print(f"{green}Found{reset} : {tar}:{pw}")
                        open(output, 'a+', encoding='utf-8').write(f'{tar}:{pw}'+'\n')
                    else:
                        failed += 1
                        print(f"{red}Not Match{reset} : {tar}:{pw}")
                        
    except Exception as e: error_msg(e)
    finally: print(f"\nDone!. Success : {success} Failed : {failed}")
        #print(wordlist)
        #print(tomd5)
            #if tomd5 == pwmd5:




def start(type, thread, target, wordlist, output):
    global success, failed
    if thread:
        #print(target)
        with ProcessPoolExecutor(max_workers=thread) as j:
            j.submit(crack, type, target, wordlist, output)
            #print(f"Done. Success :{success} Failed : {failed}")
        #print(wordlist)
    else: #print(wordlist)
        crack(type, target, wordlist, output)

def main():
    parser = argparse.ArgumentParser(description="Decrypt and Crack MD5, SHA256")
    parser.add_argument('-t', '--target', help="File List Encrypt or Single Encrypt String", metavar="Hash Target/File")
    parser.add_argument('-m', '--type', help="Specify your hash type (md5,blowfish)", metavar='type_hash')
    parser.add_argument('-n', '--thread', help="Use CPU for increase speed crack, USAGE : -n/--thread [thread], Default : 30", metavar='Thread', type=int)
    parser.add_argument('-w', '--wordlist', help="Wordlist File, Usage : -w/--wordlist [path]", metavar="wordlist")
    parser.add_argument('-o', '--output', help="Output Crack, Default: crack_result.txt", metavar="Filename", default="crack_result.txt")
    parser.add_argument('-v', '--version', help='Version Tools', action='store_true')

    if len(sys.argv) <= 1:
        parser.parse_args(['-h'])
        sys.exit(0)
    else:
        args = parser.parse_args()
        if args.version:
            try:
                print(version)
            except: pass
            
        if args.target:
            try:
                target = open(args.target, 'r', encoding='utf8').read().splitlines()
            except FileNotFoundError:
                target = args.target.splitlines()
        else:
            #parser.parse_args(['-h'])
            error_msg('File or Single Target Not Found. Usage : -t/--target <string/list>')
            
        if args.thread:
            thread = args.thread
            #print(thread)
        else:
            thread = None

        if args.output:
            output = args.output
  
        if args.wordlist:
            #global wordlist
            wl = args.wordlist
            wordlist = open(wl, 'r', encoding='utf8').read().splitlines()
            #wordlist.extend(w)
        else:
            #parser.parse_args(['-h'])
            error_msg('Wordlist Is Empty! Usage : -w/--wordlist <file_wordlist.txt>')
            
        if args.type:
            args.type.lower()
            hash = ['md5', 'sha256']
            if args.type not in hash:
                error_msg('Hash Type Not Found')
            else:
                #print(thread)
                type = args.type
                thread = args.thread
                output = args.output
                #print(output)
                #print(target)
                start(type, thread, target, wordlist, output)
        else:
            #parser.parse_args(['-h'])
            error_msg('Type Hash Not Found!, Usage : -m/--type <hash_type>')
                    


if __name__ == '__main__':
    main()
