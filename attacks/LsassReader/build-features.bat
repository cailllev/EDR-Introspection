for %%C in (standard obfuscation antiEmulation deconditioning) do (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" LsassReader.vcxproj /p:Configuration=%%C /p:Platform=x64 /p:SolutionDir=..\..\
  echo "Encrypting the created LsassReader-%%C.exe"
  ..\..\x64\Release\EDRi.exe -e ..\..\x64\Release\attacks\LsassReader-%%C.exe
)