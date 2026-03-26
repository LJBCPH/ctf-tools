import click
from rich.console import Console
from rich import print as rprint

console = Console()

@click.group()
@click.version_option("0.1.0", prog_name="ctf")
def cli():
    """CTF Winner — offensive security toolkit."""
    pass

# Register subcommand groups
from ctf.password import password
from ctf.web import web
from ctf.recon import recon

cli.add_command(password)
cli.add_command(web)
cli.add_command(recon)
