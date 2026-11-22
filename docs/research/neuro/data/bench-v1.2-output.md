windows 544 (malicious 242) in 13 captures: CTU13-42 5/47, CTU13-46 2/15, CTU13-49 20/109, IoT-1-1 113/226, IoT-3-1 38/38, IoT-42-1 0/9, IoT-44-1 0/3, IoT-48-1 11/13, IoT-49-1 9/9, IoT-52-1 16/18, IoT-60-1 3/25, IoT-7-1 25/26, Somfy-01 0/6

| method | precision | recall | FPR | false alerts / device-day | false incidents / device-day | home-IoT false alerts / device-day | AUC | folds with malicious: recall per held-out capture |
|---|---|---|---|---|---|---|---|---|
| rules@any-detector (kernel behaviour) | 0.840 | 0.955 | 0.1457 | 3.50 | — | nan | — | operating point: score > 0 |
| rules | 0.990 | 0.798 | 0.0066 | 0.16 | 0.16 | nan | 0.969 | set-42 0.00; set-46 0.00; set-49 0.00; re-1-1 1.00; re-3-1 0.95; e-48-1 1.00; e-49-1 0.00; e-52-1 1.00; e-60-1 0.00; re-7-1 0.68 |
| robust | 0.969 | 0.260 | 0.0066 | 0.16 | 0.16 | nan | 0.943 | set-42 0.00; set-46 0.00; set-49 0.00; re-1-1 0.00; re-3-1 0.95; e-48-1 1.00; e-49-1 0.00; e-52-1 1.00; e-60-1 0.00; re-7-1 0.00 |
| logreg | 0.922 | 0.983 | 0.0662 | 1.59 | 0.56 | nan | 0.985 | set-42 0.40; set-46 1.00; set-49 1.00; re-1-1 1.00; re-3-1 1.00; e-48-1 1.00; e-49-1 1.00; e-52-1 1.00; e-60-1 0.67; re-7-1 1.00 |
| maha | 0.863 | 0.967 | 0.1225 | 2.94 | 1.35 | nan | 0.984 | set-42 0.40; set-46 0.00; set-49 1.00; re-1-1 1.00; re-3-1 0.97; e-48-1 1.00; e-49-1 1.00; e-52-1 1.00; e-60-1 0.33; re-7-1 1.00 |
| lightgbm | 0.882 | 0.988 | 0.1060 | 2.54 | 1.19 | nan | 0.993 | set-42 0.40; set-46 1.00; set-49 1.00; re-1-1 1.00; re-3-1 1.00; e-48-1 1.00; e-49-1 1.00; e-52-1 1.00; e-60-1 1.00; re-7-1 1.00 |
| iforest | 0.985 | 0.822 | 0.0099 | 0.24 | 0.24 | nan | 0.918 | set-42 0.00; set-46 0.00; set-49 0.00; re-1-1 1.00; re-3-1 0.66; e-48-1 1.00; e-49-1 1.00; e-52-1 1.00; e-60-1 0.00; re-7-1 1.00 |
| rules AND lightgbm | 0.963 | 0.955 | 0.0298 | 0.72 | 0.72 | nan | 0.980 | set-42 0.00; set-46 0.50; set-49 0.95; re-1-1 1.00; re-3-1 0.95; e-48-1 1.00; e-49-1 1.00; e-52-1 1.00; e-60-1 0.33; re-7-1 1.00 |

### False alarms on an unseen benign source (15521 windows, 27 devices; never in training)

| method | false alerts / device-day | devices with any false alert | worst device (alerts/day) |
|---|---|---|---|
| rules | 0.005 | 1 / 27 | HPPrinter 0.47 |
| rules@any-detector (kernel behaviour) | 5.434 | 15 / 27 | BelkinWemoSwitch 23.40 |
| robust | 0.135 | 3 / 27 | HPPrinter 11.45 |
| logreg | 0.031 | 2 / 27 | TribySpeaker 0.46 |
| maha | 6.346 | 19 / 27 | WithingsSmartScale 24.00 |
| lightgbm | 6.346 | 14 / 27 | BelkinWemoMotionSensor 23.33 |
| iforest | 0.201 | 10 / 27 | HPPrinter 4.55 |
| rules AND lightgbm | 1.953 | 8 / 27 | BelkinWemoSwitch 21.23 |
