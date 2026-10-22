from .cli import main

# Guarded: the isolated extractor spawns child processes, which re-import the
# main module and must not run the CLI again.
if __name__ == "__main__":
    main()
