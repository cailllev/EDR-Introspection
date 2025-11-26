for %%C in (standard obfuscation anti_emulation_calc anti_emulation_sleep deconditioning_calc deconditioning_alloc) do (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" CsLoaderNoMask.vcxproj /p:Configuration=%%C /p:Platform=x64 /p:SolutionDir=..\..\
  echo "Encrypting the created CsLoaderNoMask-%%C.exe"
  ..\..\x64\Release\EDRi.exe -e ..\..\x64\Release\attacks\CsLoaderNoMask-%%C.exe
)