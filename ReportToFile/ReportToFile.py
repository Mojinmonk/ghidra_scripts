"""############################################################################
# ReportToFile.py                                                             #
# Compiled and edited by: Cody Miller on 6/11/2024                            #
# ReportToFile.py Collects all decompiled code as done by Ghidra, strings     #
# declared in the file, cross references and reports any functions across a   #
# list of known vulnerable and dangerous functions, checks the program for    #
# additional ELF headers and comments that it was packed by UPX to attempt to #
# detect embedded files, then saves each report to file for further review or #
# other means of parsing the data.                                            #
############################################################################"""


from ghidra.app.decompiler import DecompInterface
from ghidra.program.util.string import StringSearcher
from ghidra.app.script import GhidraScript
from ghidra.program.model.symbol import FlowType
import ghidra.program.flatapi.FlatProgramAPI

# `currentProgram` or `getScriptArgs` function is contained in `__main__`
# actually you don't need to import by yourself, but it makes much "explicit"
import __main__ as ghidra_app

###
# Warning
# There wasn't as much time as I would have liked to try and fine tune this, so there may be bugs in any of the methods that may call false positives or miss important details
#
# Usage
#$ analyzeHeadless <PROJECT_PATH> <PROJECT_NAME> -process <TARGET_FILENAME> -scriptPath <PATH_TO_YOUR_SCRIPT> -postScript <SCRIPT_FILENAME> <OUTPUT_FILENAME>
# Example
# ./analyzeHeadless /home/kali/headlessTest headlessTest -import /home/kali/Downloads/Week8a2.bin -postScript scriptTest.py /home/kali/headlessTest/output
###

class Decompiler:
    '''decompile binary into pseudo c using Ghidra API.
    Usage:
        >>> decompiler = Decompiler()
        >>> decompiler.decompile(reportName)
    This class and methods were authored by galoget
    https://github.com/galoget/ghidra-headless-scripts/tree/main
    '''

    def __init__(self, program=None, timeout=None):
        '''init Decompiler class.
        Args:
            program (ghidra.program.model.listing.Program): target program to decompile, 
                default is `currentProgram`.
            timeout (ghidra.util.task.TaskMonitor): timeout for DecompInterface::decompileFunction
        '''

        # Initialize decompiler with current program
        self._decompiler = DecompInterface()
        self._decompiler.openProgram(program or ghidra_app.currentProgram)

        self._timeout = timeout
    
    def decompile_func(self, func):
        '''decompile one function.
        Args:
            func (ghidra.program.model.listing.Function): function to be decompiled
        Returns:
            string: decompiled pseudo C code
        '''

        # Decompile
        dec_status = self._decompiler.decompileFunction(func, 0, self._timeout)
        # Check if it's successfully decompiled
        if dec_status and dec_status.decompileCompleted():
            # Get pseudo C code
            dec_ret = dec_status.getDecompiledFunction()
            if dec_ret:
                return dec_ret.getC()

    def decompile(self, filename):
        '''decompile all function recognized by Ghidra.
        '''

        # All decompiled result will be joined
        pseudo_c = ''

        # Enumerate all functions and decompile each function
        funcs = ghidra_app.currentProgram.getListing().getFunctions(True)
        for func in funcs:
            dec_func = self.decompile_func(func)
            if dec_func:
                pseudo_c += dec_func

        fw = open(filename, 'w')
        if isinstance(pseudo_c, str):
            fw.write(pseudo_c)
        else:
            fw.write(pseudo_c.encode('utf8'))
        fw.close()
        print ("Decompiled C code has been saved to: " + filename + "\n")

def getStrings(filename):
    '''retrieve all strings from stack and program
    found as an answer on stack overflow and lightly edited.
    https://reverseengineering.stackexchange.com/questions/27723/printing-all-strings-in-a-ghidra-project-with-python
    '''
    listOfStrings = list()
    def callback(s):
        listOfStrings.append(s)
    searcher = StringSearcher(currentProgram, 1, 1, True, False)
    searcher.search(None, callback, True, monitor)
    # The message references were my changes from the original author, they printed instead of saved
    message = 'String \\t,\\t Address \\t,\\t End Address \n'
    for i in listOfStrings:
        message += i.getString(currentProgram.getMemory()) + '\t,\t'
        message += i.getAddress().toString() + '\t,\t' + i.getEndAddress().toString() + '\n'
    
    ws = open(filename, 'w')
    ws.write(message)
    ws.close()
    print ("All strings have been saved to: " + filename + "\n")

def getDangerousFunctions(filename):
    '''getDangerousFunctions iterates through all instructions comparing to a list of dangerous functions.
    Ghidra Python script to list cross-references to dangerous functions.
    List Originally written by Craig Young
    https://medium.com/@cy1337/vulnerability-analysis-with-ghidra-scripting-ccf416cfa56d
    instructions found and lightly modified from jasonkimprojects
    https://github.com/jasonkimprojects/ghidra-scripts/blob/master/find_dangerous_functions.py
    Usage: Run the script in Ghidra's Script Manager with the target binary loaded.
    Output: Lists the cross-references to dangerous functions as hyperlinks in the Console.
    '''

    DANGEROUS_FUNCTIONS = {
        'memcpy': "# Can be used for buffer overflow or arbitrary memory write",
        'wmemcpy': "# Can be used for buffer overflow or arbitrary memory write",
        'strcpy': "# Can be used for buffer overflow or arbitrary memory write",
        'strncpy': "# Can be used for buffer overflow or arbitrary memory write",
        'wcscpy': "# Can be used for buffer overflow or arbitrary memory write",
        'wcsncpy': "# Can be used for buffer overflow or arbitrary memory write",
        'stpcpy': "# Can be used for buffer overflow or arbitrary memory write",
        'stpncpy': "# Can be used for buffer overflow or arbitrary memory write",
        'wcpcpy': "# Can be used for buffer overflow or arbitrary memory write",
        'wcpncpy': "# Can be used for buffer overflow or arbitrary memory write",
        'sprintf': "# Can be used for format string vulnerabilities",
        'vsprintf': "# Can be used for format string vulnerabilities",
        'swprintf': "# Can be used for format string vulnerabilities",
        'vswprintf': "# Can be used for format string vulnerabilities",
        'snprintf': "# Can be used for format string vulnerabilities",
        'vsnprintf': "# Can be used for format string vulnerabilities",
        'memset': "# Can be used for buffer overflow or arbitrary memory write",
        'wmemset': "# Can be used for buffer overflow or arbitrary memory write",
        'read': "# Can be used for file descriptor hijacking or denial-of-service",
        'fgets': "# Can be used for buffer overflow",
        'fread': "# Can be used for buffer overflow",
        'realloc': "# Can be used for buffer overflow or arbitrary memory write",
        'gets': "# Can be used for buffer overflow or arbitrary memory write",
        'getwd': "# Can be used for buffer overflow or arbitrary memory write",
        'scanf': "# Can be used for buffer overflow or arbitrary memory write",
        'wscanf': "# Can be used for buffer overflow or arbitrary memory write",
        'sscanf': "# Can be used for buffer overflow or arbitrary memory write",
        'swscanf': "# Can be used for buffer overflow or arbitrary memory write",
        'vscanf': "# Can be used for buffer overflow or arbitrary memory write",
        'vsscanf': "# Can be used for buffer overflow or arbitrary memory write",
        'strlen': "# Can be used for buffer overflow or arbitrary memory write",
        'wcslen': "# Can be used for buffer overflow or arbitrary memory write",
        'strcat': "# Can be used for buffer overflow or arbitrary memory write",
        'strncat': "# Can be used for buffer overflow or arbitrary memory write",
        'wcscat': "# Can be used for buffer overflow or arbitrary memory write",
        'wcsncat': "# Can be used for buffer overflow or arbitrary memory write",
        'strtok': "# Can be used for buffer overflow or arbitrary memory write",
        'strtok_r': "# Can be used for buffer overflow or arbitrary memory write",
        'wcstok': "# Can be used for buffer overflow or arbitrary memory write",
        'alloca': "# Can be used for buffer overflow or arbitrary memory write",
        'realpath': "# Can be used for buffer overflow or arbitrary memory write",
        'memmove': "# Can be used for buffer overflow or arbitrary memory write",
        'wmemmove': "# Can be used for buffer overflow or arbitrary memory write",
        'wctomb': "# Can be used for buffer overflow or arbitrary memory write",
        'wcrtomb': "# Can be used for buffer overflow or arbitrary memory write",
        'wcstombs': "# Can be used for buffer overflow or arbitrary memory write",
        'wcsrtombs': "# Can be used for buffer overflow or arbitrary memory write",
        'wcsnrtombs': "# Can be used for buffer overflow or arbitrary memory write",
        'memcmp': "# Can be used for buffer overflow, arbitrary memory write, or side channel and timing attacks",
        'wmemcmp': "# Can be used for buffer overflow, arbitrary memory write, or side channel and timing attacks",
        'fwrite': "# Can be used for buffer overflow"
}
    message = ''
    prgm = ghidra.program.flatapi.FlatProgramAPI(currentProgram)
    instruction = prgm.getFirstFunction()
    while instruction is not None:
        instructionName = instruction.getName()
        splits = instructionName.split('_')
        for i in splits:
            if i == " ":
                pass
            else:
                if i in DANGEROUS_FUNCTIONS:
                    message += "Dangerous function found: " + instruction.getName() + '\n'
                    message += "Entry point: " + str(instruction.getEntryPoint()) + '\n'
                    message += "Reason flagged: " + DANGEROUS_FUNCTIONS[i] + '\n'
                    dummy = ghidra.util.task.TaskMonitor.DUMMY
                    called_by = instruction.getCallingFunctions(dummy)
                    for caller in called_by:
                        message += instruction.getName() + " is called by: " + caller.getName() + " at " + str(caller.getEntryPoint()) + "\n\n"
        instruction = prgm.getFunctionAfter(instruction)
    if message == '':
        message += "No dangerous functions found"
    
    fs = open(filename, 'w')
    fs.write(message)
    fs.close()
    print ("Known dangerous function references have been saved to: " + filename + "\n")

def detectUPX(filename):
    '''detectUPX searches for signs that the UPX packer was used to embed a file.
    Based on code from guide below
    https://www.archcloudlabs.com/projects/ghidra_scripting_01/
    '''
    message = ""
    prg = ghidra_app.getCurrentProgram()
    addrUPX1 = find("UPX")
    addrUPX2 = find("This file was packed with the UPX executable")
    if addrUPX1 == prg.getImageBase() or addrUPX2 == prg.getImageBase():
        if addrUPX1 == prg.getImageBase():
            message += "Packed with UPX evidence found at: " + str(addrUPX2) + '\n\n'
        else:
            message += "Packed with UPX evidence found at: " + str(addrUPX1) + '\n\n'
    headersMatch = findBytes(prg.getMinAddress(), "ELF", 100)
    if len(headersMatch) > 1:
        for match in headersMatch:
            message += "Additional Elf header found to investigate at: " + str(match) + '\n'
        message += '\n'
    if message == "":
        message += "No evidence of UPX or additional headers, though encoded headers may have been missed."
    
    us = open(filename, 'w')
    us.write(message)
    us.close()
    print ("Any clues to packing and file embedding have been saved to: " + filename + "\n")

def run():
    # getScriptArgs gets argument for this python script using `analyzeHeadless`
    args = ghidra_app.getScriptArgs()
    if len(args) > 1:
        print('[!] Wrong parameters!\n\
        Usage: ./analyzeHeadless <PATH_TO_GHIDRA_PROJECT> <PROJECT_NAME> \
        -process|-import <TARGET_FILE> [-scriptPath <PATH_TO_SCRIPT_DIR>] \
        -postScript|-preScript decompile.py \
        <PATH_TO_OUTPUT_FILE_MINUS_FILE_TYPE_EXTENSION>')
        return
    
    # If no output path given,
    # <CURRENT_PROGRAM>_decompiled.c will be saved in current dir
    if len(args) == 0:
        cur_program_name = ghidra_app.currentProgram.getName()
        output = '{}_decompiled.c'.format(''.join(cur_program_name.split('.')[:-1]))
    else:
        output = args[0]

    # Do function decompilation process and save to file
    decompiler = Decompiler()
    decompiler.decompile(output + '_functions.txt')
    # all code in this method above this point was written by galoget with the decompiler class

    # Find and save strings file
    getStrings(output + '_strings.txt')
    
    # Find and save dangerous function references to file
    getDangerousFunctions(output + '_dangerous_functions.txt')

    # Find and save report on packing detection to file
    detectUPX(output + '_detected_packing.txt')

    # Last command ran and end of run function
    print ("All finished!")


# Starts execution here
if __name__ == '__main__':
    run()
