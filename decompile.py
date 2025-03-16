import sys
import tempfile
from typing import List
import angr
from angr.analyses import CFGFast, Decompiler
from angr.knowledge_plugins import Function
import warnings
import os

warnings.filterwarnings('ignore')

def decompile(binary_path: str, output_file: str):
    if not os.path.isfile(binary_path):
        print(f"Erreur : le fichier {binary_path} n'existe pas.")
        sys.exit(1)
    
    p = angr.Project(binary_path, auto_load_libs=False, load_debug_info=False)
    
    cfg: CFGFast = p.analyses.CFGFast(
        normalize=True,
        resolve_indirect_jumps=True,
        data_references=True,
    )
    
    p.analyses.CompleteCallingConventions(
        cfg=cfg.model, recover_variables=True, analyze_callsites=True
    )

    funcs_to_decompile: List[Function] = [
        func
        for func in cfg.functions.values()
        if not func.is_plt and not func.is_simprocedure and not func.alignment
    ]

    with open(output_file, "w") as f:
        f.write("// Décompilation du binaire : " + binary_path + "\n\n")

        for func in funcs_to_decompile:
            try:
                decompiler: Decompiler = p.analyses.Decompiler(func, cfg=cfg.model)

                if decompiler.codegen is None:
                    f.write(f"// Pas de sortie de décompilation pour la fonction {func.name}\n\n")
                    continue

                f.write(f"// Décompilation de la fonction {func.name} :\n")
                f.write(decompiler.codegen.text)
                f.write("\n\n")

            except Exception as e:
                f.write(f"Exception lors de la décompilation de la fonction {func.name}: {e}\n\n")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Erreur : veuillez fournir le chemin du binaire et le fichier de sortie.")
        sys.exit(1)

    binary_path = sys.argv[1]
    output_file = sys.argv[2]


    decompile(binary_path, output_file)
