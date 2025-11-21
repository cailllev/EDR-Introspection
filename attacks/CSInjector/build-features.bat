for %%C in (standard obfuscation anti_emulation_calc anti_emulation_sleep deconditioning_calc deconditioning_alloc) do (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" Injector.vcxproj /p:Configuration=%%C /p:Platform=x64 /p:SolutionDir=..\..\
  echo "Encrypting the created Injector-%%C.exe"
  ..\..\x64\Release\EDRi.exe -e ..\..\x64\Release\attacks\Injector-%%C.exe
)