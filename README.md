# Crear el entorno virtual con todas las dependencias necesarias
```Terminal
conda env create -f environment.yml
```

# Si agregas alguna dependencia hacer
```Terminal
conda env export --name metricas_cripto > environment.yml
```