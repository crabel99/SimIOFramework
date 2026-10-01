from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[4]
here=Path(__file__).resolve().parent
build=root/'build/pukcc-verifier-native'
build.mkdir(parents=True,exist_ok=True)
command=['clang++','-std=c++17','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',
 '-I'+str(here/'fakes'),'-I'+str(root/'cores/arduino'),
 '-I'+str(root/'libraries/Crypto/src/utility/pukcc'),str(here/'main.cpp'),
 str(root/'libraries/Crypto/src/utility/pukcc/PukccEcc.cpp'),
 str(root/'libraries/Crypto/src/utility/pukcc/PukccEcdsa.cpp'),'-o',str(build/'test')]
subprocess.run(command,check=True)
subprocess.run([str(build/'test')],check=True)
