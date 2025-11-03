for %%C in (standard encryption anti_emultaion_calc anti_emultaion_sleep deconditioning_calc deconditioning_alloc) do (
  "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" Injector.vcxproj /p:Configuration=%%C /p:Platform=x64
)