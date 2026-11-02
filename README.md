![A long practice sheet covered in single breath strokes, a cleared centre with a brush resting across an ink stone, no title anywhere](intro-banner.png)

> Medium noted first: sumi ink on canvas cream practice paper, Bitcount Prop Single in pigment ultramarine, a studio inventory entry.

# cha-audit-firewall-rule-analyzer

![The sumi brush mark: a diagonal bamboo handle, a dark tuft, one bead of ink at the point, one finished stroke beneath](logo.png)

![The practice sheet with its title band brushed across the top sheet's upper margin](banner.png)

![A practice table in three depths: the back stays still under a slow change of light, one new line is drawn across the middle sheet in a single pass, and a water drop ripples in the ink stone](scene.svg)

# cha-audit-firewall-rule-analyzer
Analyzes firewall rules (iptables, firewalld, or Windows Firewall) to identify overly permissive or redundant rules, and can audit a YAML or JSON configuration against a baseline.

![A minor divider: a centred cluster of stitch perforation dots](sep-light.svg)

## Install
```
git clone https://github.com/ShadowGuard-AI/cha-audit-firewall-rule-analyzer
cd cha-audit-firewall-rule-analyzer
pip install -r requirements.txt
```

![A major divider: stitch perforations appearing dot by dot across the full page width](sep-heavy.svg)

## Usage
```
python3 main.py -t TYPE [-c CONFIG] [-o OUTPUT]
```

> Ink stone tray: Type Is Required. The type choice, -t, also written --type, is the one required part of the command line, with the three accepted values iptables, firewalld, and windows.

![A minor divider: a centred cluster of stitch perforation dots](sep-light.svg)

## Parameters
- `-h`: show help message and exit.
- `-t`, `--type`: the type of firewall to analyze, required: `iptables`, `firewalld`, or `windows`.
- `-c`, `--config`: path to the configuration file (YAML or JSON).
- `-o`, `--output`: path to the output file for the report.

![A major divider: stitch perforations appearing dot by dot across the full page width](sep-heavy.svg)

## Verified behavior
- Without `-c`, the tool runs the live firewall command for the chosen type: `iptables-save`, `firewall-cmd --list-all`, or `netsh advfirewall show allprofiles`. That live step was not run in this wave, because those commands are not available in this environment.
- Live run not possible in this environment: the `jsonpath_ng` package is not installed here and installs are not permitted in this wave. The parameter list above is taken from the argument parser in `main.py`, and the file compiles cleanly.

> Ink stone tray: Live Run Not Performed in This Wave. The cautions above are kept at full size: the live commands were not available in the documenting environment, and the package named there was not installed, with installs not permitted in that wave.

![A minor divider: a centred cluster of stitch perforation dots](sep-light.svg)

## License
MIT License, see LICENSE.
