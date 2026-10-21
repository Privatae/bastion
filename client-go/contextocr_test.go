//go:build !windows

package main

// Gates for OCR (contextocr.go) — the literal words on a picture, read
// on the user's own machine.
//
// EVERY ONE OF THESE DRIVES REAL TESSERACT through a real ctx_extract management
// frame. A unit test of the argv builder would have passed on the machine this
// was written on and still shipped a lane that cannot OCR, because the failure
// mode here is not a wrong flag — it is an engine that exits 0 and reads
// nothing. So the fixtures are real: a real image-only PDF, produced by
// rasterizing a text PDF through ghostscript's pdfimage8 device (verified: its
// text layer is EXACTLY ZERO characters, which is the property that makes it a
// scanned document and not a text one), and a real 1-bit PNG of known words.
//
// Both are small enough to live in the source and regenerable from the recipe
// above — nobody inherits a fixture they cannot rebuild.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The words on both fixtures. The FIRST line only — the second exists so a test
// can tell "read the page" from "read the top of the page".
const ocrFixtureLine1 = "OCR FIXTURE ALPHA zulu yankee"
const ocrFixtureLine2 = "second line xray whiskey victor"

// A two-page PDF containing nothing but a grayscale raster of those words:
//
//	ps2pdf fx.ps fx.pdf
//	gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfimage8 -r150 -sOutputFile=scanned.pdf fx.pdf
//
// Measured: `pdftotext scanned.pdf -` returns 0 characters of text (two form
// feeds and nothing else), while the pages are covered in words. That is the
// exact document this whole slice exists for.
const scannedPDFB64 = "JVBERi0xLjMKJcfsj6IKJSVJbnZvY2F0aW9uOiBncyAtcSAtZE5PUEFVU0UgLWRCQVRDSCAtc0RFVklDRT1wZGZpbWFnZTggLXIx" +
	"NTAgLXNPdXRwdXRGaWxlPT8gPwo0IDAgb2JqCjw8Ci9MZW5ndGggNSAwIFIKL1N1YnR5cGUgL0ltYWdlCi9XaWR0aCA4NzUKL0hl" +
	"aWdodCA0NTgKL0NvbG9yU3BhY2UgL0RldmljZUdyYXkKL0JpdHNQZXJDb21wb25lbnQgOAovRmlsdGVyIC9GbGF0ZURlY29kZQo+" +
	"PgpzdHJlYW0KeJzt2Nt6YrmuBlDe/6Wzv726ksxp65cNRQUIY1x0gw+y5EOS7o8PAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAODj8j+39wNrl6NFf5qWZ4eRl++O45hp" +
	"Upp+7JrX2skwBl3s00ZjHb5OMrV0sW9z32jPvuwTWt212L9/VePAw5QUPi5041P7Hr2f/3l82bpXdJVkakkL3u6+0Z572YdUurC6" +
	"bdde1dWvxdO444w6erPQrU/t8tH1buxU1XpF0cu0+wVvd9dgz73sYyrtra7b1Vf1qltXxZu/NAvNKxZBQoa72U9FVM2bRZ+WTmn3" +
	"C97ursGeetkHVdpaXbfrr6qntr11Ke1+wdvdNdgzL3vfbbuP8Sw3vxdfyoZzR1y/mF+H2rmh+xleeSDTe1lEGdpPc3cKSQve7kEX" +
	"8IeXvfeu3Um6i+UvmrFhLiiVGCs/dxym1zN2bmj/mPr8O4eLf9NTK5beKeSel+ZBF/Anl73cf9fuY3Vzrr2qqcRY+dDxNT8E2r+h" +
	"t+XfSWcYo4S1ryzknpfmrhewC1adah9ou3kx6LhpT/jUqrZ0I+b7cs+n9vV9O07f0md43YH8Gbxd852e2vpKj5drmDBtR7VcuUY1" +
	"pvjP3CnI2JO/rP4DOBT+2VMMmnbjWVQZHdOMmzCNnOeu1ik7Tjv1VE/tfLwhYp9su7FxdJfkZVREmrajWq5coxpz2rnhnP77PHek" +
	"z2OgUFcq+6Mas5j5MHVG46HFjOfuxd5sdGzt8XZLn+FVB/I5NmW8XdtuIXHBee3zlg0TpoKr5co1hsrGydNB/fd57pk+XoYVLnvN" +
	"uezmDj+JOqF4aPXAf/bUthLuW/oM8zrd0uOkGKVbu7gscXSTZTl/GD8VXCVXL3EaNC4wp53qmWa26cfmpuxpTD3vgdpCYn8xsP4+" +
	"jexOYR66lXDf0mdYZZWq/e4ch8V53cBy6WJ0XWLM7yef2jzkWMRc7LxV5ZjYPBfb/Om1tWc/qS0k9o8DR5sjUwZNmFufWshwN/tz" +
	"1HFYnDe0F3V3q+cFc3qrV7Q1KESd/n5M4ecvX5/KHenrLYs/71Z1ADt79qNCQmlr6nHxsixGpgzWcfZb+gz381/e0vzU6vh1X/3U" +
	"Nu5NEfvct1XEbtWnwXHh72+fn8oSw/Aig1Buc4nmgh4mJPTVvEi4vytbI+Mu/bvfan1WbQHlknFeGX73qTULxpXqLakD5UGh7JBE" +
	"zvP7259PY4SQwkZml7RSiv14q+1bJLy4LYuRIYM2UBqeWvoMt9Mvgw5RNrdnt5BmwbRQF2nqyYPm0HnEuapUQdjfUHGzEaHgrWvx" +
	"YHVC34XsHfFoe6Gy48o4fUufYV6nX/g8LUbp9mZZSLNgWqiLNPXkQaHuYURVVqqg3IH4oyg0N3v1Pk8tfl8tVHXk/a3j9C19hjnf" +
	"ft3q29ZT2y+k+xbWSbGn7VgMqgsvax4KS2mETZj35/Lbn1r9l3Duz9Pj8O2OboPLOH1Ln+GivClmffwxShd9VUi3YJ1bjD1tx2JQ" +
	"EX0cEDIrQhZPbVXjRumLisuWB6uPcNqj0JsO+ZpbFzYtBdrZ0+nwY4Yx3XrZcPzXF70upF2wzC3HngpeDKoTrbIrwxdpfI0/Lxpq" +
	"3Ch9bFvs5lPIdZQHMjQtT3nZXp74Yb/XcfqWPsOwSMoyHH+M0kVfFNIuWKXWxJ4KXgwqEy2yC+GLNL5yrDZuY2uWQ5Z78ATiQeXL" +
	"OB3X/Z9anrFIdxpzbW9wqS2idNEXl6NdsMisiz2luhhUrVD8UkvhizSqT+UedM1N1es9eAbzUVXXKPwFlianZeL6RfD6cm1sapV/" +
	"GF6vkZKcLaJ00ee+atvrBYvMmthz3MWgXHw1eApfpDF+mrPptybl1MzYCPLTxrPa/F58ObSkZeL6e8HrOF2Cd31qqSVG6aLvhNyI" +
	"1WxSfAvVj8km1cuXMpcpfJFyWjYEWmd2KcI8/VM77+S8rR+nlqF7rjFVGCsvtvW2pzYUUEWcIlxqG9kfR8YYsegm5M6CVe2n3Kcc" +
	"qrhxUJ3qoTsstfXUFp/D8Fh3HNIV9DDzcZ1y7LrnIlOFsfJmW6stzLta599nWNY2p7lIJMaIRZd9c8Rl5YunNte0KL5L9djdhi8y" +
	"LpY9B6p/TY3NXd0v8dRWe950z6NThbHyQ0eIvv476uYMqxMr0lwcZYwRiy77pojrJH7mqc2bmKaeh4WN6HII8VNGzZi2oMdZpJ27" +
	"5+H93sS167lFsDpOzr/PsDixHL5cMkZpiy77przigrnw6gp/TO3F5OGVrJaeZl791Mq3FuqKu9eMSTMfbquyuONty7E9rtwG2/+t" +
	"eW2Gl1ode5X4HCMWXfZ1O5GixdyPDYf2c4wwKORa/6kz/9CJBdWFzLl3zUOIPKbb+wdr6trqf7inT/CHbe3G5pYVo+642Tc8lvS6" +
	"4bU93X32U5Vf6fku9vNlBHfwfPfaU+M3esJ7/YQpwd/p/j/g4zxhSvB3nvKleWr8Pk/50jw1fp/nvNTPmRUAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAv9vlf9rmMOT15EKWJf7cHvya3WbgqfU9uwPu5tfsNgNPre/ZHXA365V+zXm8GU+t79kd" +
	"cDee2m/lqfU9uwPuxlP7rTae2q/xF0U90348Uy7s89T+9dS7e6ZcXkjatq55f3ju/Gq79ak105pZvcPUf3KdLqeq90bu5fMvL/9e" +
	"Losb8G9SeyGXb3VzGr4R5fN77PuvbeOpHT53QWPax84U/uN4/Q8FVRPmr1NT/eVcc45XbOg6mTh6ne28xU3wYnM2bsDHe7uc1e1p" +
	"+F6U8mBOJ1Ncg+8h0+cmaEp76J4+f96IqfcyzyjTW6Q8/C47p5/nDkPS57rudbZ5xKkn7sQy4Wpj39ZlVLen4YsoxauIU/7mqaX8" +
	"Ur1T9FPMWGhZ3CrlcbFc97xSuX5M5e+yXfyUOAdPi4Wi/s2f4i8mbNF1zfn6zB0pUnUS84Q+aD7wsd4h+HQjwgrFYjnlMHOVfVPI" +
	"FKQ/xauy3d/tsTGcSb2x76vYrbp5Gh5mDpegOJ4U6fqn1gWNh/vZPqw5XJJ25SK7If6UZmiuNqvZ0CG9Mfnrs40juvWr/Q0Jzxv7" +
	"vtqjDs3TaZR723+p2q99avMK67v13T50DznMX8LKTc7HkH32YWpuLpNPCSyzvTJI3OvuBrz3M/t/3f7OYy5z+9ycHsgq0rVPrRiU" +
	"2ougY++lCFp8iVkUOR8XSfO6/c/NZfJpPzaz3Upl+qlTlVGdm5cWfuZUOze3f31bbvTcU7X/9VNLaYeaL9NtrS/EVhbz6NMqffah" +
	"kin6n8ZF7uVS6x0+jehPqhne7dh7K69d3Lmwa+XRTx+nQOuLHo4snWtz4HXRTQ3T4Km2dsLXv+edK+5uqGRa4XIpO3Ld+9n2f8nE" +
	"fakzyOW+s/L0LpWPuO1jc3nWp47FZama10Fj2rHmpoYpXL1aiv7n35//vPaphUcVCst1b2Y7H8kVE6tBYwrF/PfTnNDUMx7xKUTd" +
	"UF2VYspG5HXQ7af2UXTVDXOcWMKUz/jP25/aMHWqLNe9n+3uSc0jqkFjCsX8d1QcUTi7sO37Gx0PcCPyOuhdn1qMcyqhCv7Zc9iz" +
	"9KCGMJf5y3n5LqU63+1sPbWfMZ5ROLu07dsbHQ8wRA7HGYLe8w/I04hT32kziuDD6zp9KWrNPcXfi1+fixh13ZvZTiO+Yiw2sd49" +
	"T61zOqO0v13zeEWqGXGBsGB1aXLQfC1SqXXOU6hT35+eZq3vAZ/fbnxqH8OxfP82Pqe/ymWd7SXXn2a2GYznVq78xr4PNZ1McUuK" +
	"h3OJGz1emmHldr3D572gyzrT5ajTG0Y2S53DT6Nz7Dr/Q7BQalf3Mtt6RH9SqwymcwtLv5OwRenswi3Z3uj+AH/oqV0Od2t8QGWh" +
	"ZXnLy3tOqryt47pfPWlDp6hlgnUud3xqm1s0F/jO0n0L+xgO+FIM33pqp0h//9S2ftZ/rjWsme9KfmpT7HHE9GUOVy5UrViWWr21" +
	"arWtbC9TY7dQsebGDXhj4ZDm7Z0OODRXu16tNke681Nbxjz3VzGrgtp8qwHT6Lxuvf/tsaTPxU+GlG05oq5/3pb1hvVrv5HL7NQ+" +
	"/MapB8co66dWzRmzq+c2g6a054I/FjeiSy7nOy8yrXPNU5vWj2GburezXTy1aSe+lmwSnjf2faUdCvuW2tM+b7yKYlIz/sqgqd7p" +
	"8/qpzZ3LXa1H5w367gmrX+rRfd3LbKsRG8Gr1IoUVou/j3aHiqML7emoq1HzlOH6lePHY10GLU94jhj+k6LLLkYvB9RbVW3QWOJU" +
	"SVXqsu5ltqunFoKXuc0prBZ/J+mQwtEtTrQKMoyZZowd5fjD5y5ozO/YWXzLdcb//JnDlwPq2advVc/lKE+tfjZ2NS/T3Y89NjWj" +
	"msXfS7qb6YxC+/pMyxlXpbod9e/DNmF+5vqkY+nHh/b7JFMm2DTA33mtC/Va2cK31/rZ/VrZwsFr3d3Xyha+vdavidfKFj5d+/8q" +
	"Huu1soWD17q7r5UtHLzW3X2tbOHgte7ua2ULAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAX/4Pl+sREgplbmRzdHJlYW0KZW5kb2JqCjUgMCBvYmoKMzY3OQplbmRvYmoKNiAwIG9iago8PAovRmlsdGVyL0ZsYXRl" +
	"RGVjb2RlL0xlbmd0aCA4IDAgUgo+PgpzdHJlYW0KeJwzMTLQMwADBRA0MrTUszCBc5NzufQ9cw0VXPIBma8IHgplbmRzdHJlYW0K" +
	"ZW5kb2JqCjggMCBvYmoKMzQKZW5kb2JqCjcgMCBvYmoKPDwKL0NvbnRlbnRzIDYgMCBSCi9UeXBlIC9QYWdlCi9QYXJlbnQgMiAw" +
	"IFIKL01lZGlhQm94IFswIDAgNDIwLjAwMDAwMCAyMTkuODQwMDAwXQovUmVzb3VyY2VzIDw8Ci9YT2JqZWN0IDw8Ci9JbTEgNCAw" +
	"IFIKPj4KPj4KPj4KZW5kb2JqCjkgMCBvYmoKPDwKL0xlbmd0aCAxMCAwIFIKL1N1YnR5cGUgL0ltYWdlCi9XaWR0aCA4NzUKL0hl" +
	"aWdodCA0NTgKL0NvbG9yU3BhY2UgL0RldmljZUdyYXkKL0JpdHNQZXJDb21wb25lbnQgOAovRmlsdGVyIC9GbGF0ZURlY29kZQo+" +
	"PgpzdHJlYW0KeJzt2NtaY8euBlC//0uzv73SDZ5T+lVl4wYbxrhI7DqopDoAydsbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPB2+Z/7+4G1y7VFf5qWZ4eRl4+O6zFl" +
	"Upp+3VXX2skwBl3s00ZjH75PMrVMse/z2GjPu+yDt+1xVnct9u9f1TjwakoKHxe686l9jN7P/zi+bd0ruksytaQF7/fYaE+67N5Z" +
	"fovVbbv1qq5+LR7GXc/oow8L3fvULm9T78ZOda03FL1Me17wfg8N9qTLbp/m11tdt5uv6k23rotXvwwL1RWbICHD3exLEV3zZtGH" +
	"pVPa84L3e2iw51x2/zi/3Oq6re/LNHuM8tFxHFW/DAvVFfcz3M2+FNE137a1c9rzgvd7aLDnXHb/OL/aOaHN782XtuHYEddv5veh" +
	"dm7ofoY3HkY4v92iD3N3CkkL3u+bLt8XLlv3+GneWrqL7S+ac0OtJVUXiz52XE3vZ+zc0Pkx3X8WVxf/rqfWLL1TyCPvyzfdvS9c" +
	"trm8X7Lu2urm3HpV08WIRZ863ueHQPs39L78J+nmxyhh7RsLeeR9eejdm4J1pzoH2m6eBx2Wemi5n9UlUy9jmjJf5NU6bcff79tx" +
	"5pY5w9uu8Z/B2zU/6Kmtr/S1JlLZjm65do1uTPOfuSXIuSd/if89GppPMXIKQ1XfpKvmOvu4CWVknbtap+24HGzEmVvmDIfDzJlu" +
	"1/zZpxYXrGsfd+w0oWxHt1y7RjfmsHOnc/rvc+1In8+BQl2p7LdmzEZV36Ov5XxoMdnavdibjY6tPd5umTNclNcvnTLerm23kLhg" +
	"Xfu4ZacJpeBuuXaNU2XnyeWg/vtce8rHy2mFy15zLvuUwljV9+griYfWD/xnT20r4bllzjCvMy19nhSjTGs3lyWOHrJs55/Gl4K7" +
	"5PolDoPOC9S0Uz1l5ph+bB7K7pJfXt8vNRYS+5uB/fcycjqFOnQr4bllzrDLKlX70XkeFudNA9ulm9F9iTG/r3xqdch1EbXYulXt" +
	"mNhci1396bW1cV9kLCT2nweebY5MGQxh7n1qIcPd7I9Rz8PivFN7U/e0el4wp7d6RVuDQtTy92MKX7+8f2p3ZK63Lf64W+kAdvbt" +
	"y6xyXCS7uCyLkSmDdZz9ljnD/fyXtzQ/tT5+39c/tY0708Q+9m0VsVv1YXBc+OPb309tiWF4k0Eod/0b4xmEZN6bF8nOd2VrZDNp" +
	"ilR75pY5w653LKBdMs5rw+8+tWHBuFK/JX2gPCiUHZLIeX58+/PpHCGksJHZJa2Ux3y31fYtsl3clsXIkMEYKA1PLXOG2+m3QU9R" +
	"Nrdnt5BhwbTQFKn05EE1dB5xrCpVEPY3VDxsRCj41r+NvkOfzkeWe0d8tr1Q23FjnLllzvCG42jmnRJOc/q9WRYyLJgWmiKVnjwo" +
	"1H0a0ZWVKmh3IP4oCs3DXtX96ad9pz6fjzRvO+Lh6u535P3t48wtc4b753Ec2H3bemr7hUzfwjopdtmOxaC+8LbmU2EpjbAJdX8u" +
	"D3pq/axv1WdU9mh7ehy+3TFtcBtnbpkz3D+Q6fhjlCn6qpBpwT63GLtsx2JQE/08IGTWhGye2qrGjdJ3Kn6qh3bfUyvHVR9KWihm" +
	"UL6nQLV5bpkz3D6S9vT/5VMbF2xzy7FLwYtBfaJddm34Jo338cdFQ40bpZ/b2r1rd+v75DraAzk1LU952R5/HoXtqq1zy5zh9pm0" +
	"p/8cT63p6va09ORBbaJNdiF8k8Z7jt3GbWzNcsj192mzvlM8qHwZy3E9/qnlGYt0y5hbe4NLbxFlij7u62LBJrMpdkl1Mahbofml" +
	"lsI3aXSf2j2Ymoequ60b53+Lmlh3jcJfYGlyWiau3wTvd2x9sVY/Kube3iVYRJmi175u2/sFm8yG2DXuYlAuvhtcwjdpnD/VbOat" +
	"STnlEp/wpZWz2vzefLlqScvE9feC93GmBB/61FJLjDJF3wm5EWvYpPgWuh+TQ6qXd20uJXyTclo2BFpndmnCpJ/+z+Owk3Vb3w4t" +
	"p+5aVyo0bkCzrfc9tVMBXcQS4dLbyL453RojFj2E3Fmwq/2Qe8mhixsH9aledYeltp7a4nMYHuvuU2i25Ck0yTV/j7XdtZZUXCx6" +
	"2NZup7o4U/5zhm1tNc1FIjFGLLrtqxGXlS+eWq1pUfyU6nX3GL7JuFn2GKj/NXVunup+iae2ym7orqNTcbHoq44Qff131N0ZdifW" +
	"pNm1NnmXGLHotq9EXCfxNU+tbmKaehwWNmLKIcRPGW1MzVV9i0VyubsOn/cmrt3PbYL1cXL+c4bNueTw7ZIxylh021fyigvmwrsr" +
	"/Fbam8mnV7Jausy8+am1by3UFXevjqkb8lxP7ZThfvdOy3V7XHkMtv9b89YMu4Op4afWGGUsuu2bdiJFi7lfN1y1H2OEQSHX/k+d" +
	"+kMnFtQXUnOfmk8hypi6Ic/21Pq/1m7p/3ZPn+AX29qNzS1rRj1ws0OoaYX0uuG1Pd199lOVH+n5LvbzZQQP8Hz32lPjJ3rCe/2E" +
	"KcHnPOf/x3vClOBznvKleWr8PE/50jw1fp7nvNTPmRUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9vlf8bm" +
	"MOT15EKWJX7dHvyY3ebEU5t7dgc8zI/ZbU48tblnd8DDrFf6Mefxy3hqc8/ugIfx1H4qT23u2R3wMJ7aT7Xx1H6MTxT1TPvxTLmw" +
	"z1P711Mf7plyeSFp26bm/eG5873t3qc2TBtmza6m/pPrdDlUvTdyL59/efn3clncgH+T2gu5fOib0/CNKH+/x77/2jae2tXnKWhM" +
	"+7ozhX+7vv5XBXUT6tfS1H851pzjNRu6TiaOXmdbt3gI3mzOxg14+90uR317Gr4XpT2Yw8k01+BjSPk8BE1pn7rL5783ovRe6ow2" +
	"vUXKp99lx/Tz3NOQ9Lmve51tHnHoiTuxTLjb2F/rcta3p+GLKM2riFM+89RSfqneEv0QMxbaFrdK+bxYrruu1K4fU/lctoufEsfg" +
	"abFQ1L/5U/zFhC26rTlfn9qRInUnUSfMQfOBn+s9BS83IqzQLJZTDjNX2Q+FlCDzKd6U7f5unxvDmfQb+3s1u9U3l+Fh5ukSNMeT" +
	"It3+1Kag8XD/tp/WPF2SceUmu1P8kmZo7jZr2NBTeufkb882jpjW7/Y3JFw39vcajzo0l9No93b+0rXf+tTqCuu79dF+6j7lUL+E" +
	"lYecr0PO2YepublNPiWwzPbGIHGvpxvwu5/Z/5v2t4651PbanB7IKtKtT60ZlNqboOfeSxO0+RKzaHK+XiTNm/Y/N7fJp/3YzHYr" +
	"lfJTpyujOzcvLfzM6Xautr9/W2507enaP/3UUtqh5ku5rf2F2Mqijj6sMmcfKinR/zQucm+XWu/wYcR8UsPwacd+t/baxZ0Lu9Ye" +
	"fflYAq0vejiydK7DgfdFDzWUwaW2ccL7v+vONXc3VFJWuFzajlz3frbzXzJxX/oMcrm/WXt6l85b3PZzc3vWh47FZema10Fj2rHm" +
	"oYYSrl8tRf/z77//vPWphUcVCst1b2Zbj+SGid2gcwrN/N9nOKHScz7iQ4i+obsqzZSNyOug20/trenqG2qcWELJ5/zP+5/aaWqp" +
	"LNe9n+3uSdUR3aBzCs3836g5onB2Ydv3Nzoe4EbkddCHPrUY51BCF/xvz9WepQd1CnOpX47LTyn1+W5n66l9jfMZhbNL27690fEA" +
	"Q+RwnCHoI/+APIw49B02owl+el2HL02tuaf5e/H9cxOjr3sz2zLiPcZiE/vd89QmhzNK+zs1n69INyMuEBbsLk0Omq9FKrXPuYQ6" +
	"9P3pGdb6GPD3251P7e10LB+/jY/pr3JZZ3vJ9aeZYwbnc2tX/sU+DjWdTHNLmodziRt9vjSnlcf1rj7vBV3WmS5Hn95p5LDUMXwZ" +
	"nWP3+V8FC6VOdS+z7UfMJ7XKoJxbWPo3CVuUzi7cku2Nng/wi57a5epunR9QW2hb3vLyHpNqb+t53feetKElaptgn8sDn9rmFtUC" +
	"f7N038I+hgO+NMO3ntoh0uef2tbP+r9rndbMdyU/tRL7PKJ8qeHahboV21K7t9attpXtpTROCzVrbtyAXywcUt3ecsChudv1brUa" +
	"6cFPbRnz2N/F7Aoa8+0GlNF53X7/x2NJn5ufDCnbdkRff92W9YbNa/8il+rQfvqN0w+OUdZPrZtzzq6fOwwqadeC3xY3Ykou51sX" +
	"Kevc8tTK+jHsUPd2tounVnbifckh4bqxv1faobBvqT3t88araCYN428Mmuotn9dPrXYud7UfnTfooyesfulHz3Uvs+1GbATvUmtS" +
	"WC3+e4w71BxdaE9H3Y2qU07Xrx1/PtZl0PaEa8TwnxRTdjF6O6Dfqm6DziWWSrpSl3Uvs109tRC8za2msFr8N0mHFI5ucaJdkNOY" +
	"MuPc0Y6/+jwFjflddzbfcp3xP39q+HZAP/vwreu5XMtTu5+NU83LdPdjn5uGUcPiv0u6m+mMQvv6TNsZN6W6HfXzYYcwX3N90rHM" +
	"40P7Y5JpExwa4HNe60K9Vrbw4bV+dr9WtnDlte7ua2ULH17r18RrZQt/3fr/Kr7Xa2ULV17r7r5WtnDlte7ua2ULV17r7r5WtgAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPDu/wBvapGDCmVuZHN0cmVhbQplbmRv" +
	"YmoKMTAgMCBvYmoKMzcyNgplbmRvYmoKMTEgMCBvYmoKPDwKL0ZpbHRlci9GbGF0ZURlY29kZS9MZW5ndGggMTMgMCBSCj4+CnN0" +
	"cmVhbQp4nDMxMtAzAAMFEDQytNSzMIFzk3O59D1zDRVc8gGZrwgeCmVuZHN0cmVhbQplbmRvYmoKMTMgMCBvYmoKMzQKZW5kb2Jq" +
	"CjEyIDAgb2JqCjw8Ci9Db250ZW50cyAxMSAwIFIKL1R5cGUgL1BhZ2UKL1BhcmVudCAyIDAgUgovTWVkaWFCb3ggWzAgMCA0MjAu" +
	"MDAwMDAwIDIxOS44NDAwMDBdCi9SZXNvdXJjZXMgPDwKL1hPYmplY3QgPDwKL0ltMSA5IDAgUgo+Pgo+Pgo+PgplbmRvYmoKMSAw" +
	"IG9iago8PAovUGFnZXMgMiAwIFIKL1R5cGUgL0NhdGFsb2cKL0luZm8gMyAwIFIKPj4KZW5kb2JqCjIgMCBvYmoKPDwKL0NvdW50" +
	"IDIKL0tpZHMgWzcgMCBSIDEyIDAgUiBdCi9UeXBlIC9QYWdlcwo+PgplbmRvYmoKMyAwIG9iago8PAovUHJvZHVjZXIoR1BMIEdo" +
	"b3N0c2NyaXB0IDEwLjA2LjApCi9DcmVhdGlvbkRhdGUoRDoyMDI2MDkxMjIzMzAzM1owMCcwMCcpCj4+CmVuZG9iagp4cmVmCjAg" +
	"MTQKMDAwMDAwMDAwMCA2NTUzNiBmIAowMDAwMDA4Mzk3IDAwMDAwIG4gCjAwMDAwMDg0NTggMDAwMDAgbiAKMDAwMDAwODUyMyAw" +
	"MDAwMCBuIAowMDAwMDAwMDk1IDAwMDAwIG4gCjAwMDAwMDM5MzEgMDAwMDAgbiAKMDAwMDAwMzk1MSAwMDAwMCBuIAowMDAwMDA0" +
	"MDc1IDAwMDAwIG4gCjAwMDAwMDQwNTcgMDAwMDAgbiAKMDAwMDAwNDIxOSAwMDAwMCBuIAowMDAwMDA4MTAzIDAwMDAwIG4gCjAw" +
	"MDAwMDgxMjQgMDAwMDAgbiAKMDAwMDAwODI1MSAwMDAwMCBuIAowMDAwMDA4MjMyIDAwMDAwIG4gCnRyYWlsZXIKPDwKL1NpemUg" +
	"MTQKL1Jvb3QgMSAwIFIKL0lEIFs8MjRBNDAxOThFRTI3MERFRUVDQ0JDNzZGQzkyODJFMDM+PDI0QTQwMTk4RUUyNzBERUVFQ0NC" +
	"Qzc2RkM5MjgyRTAzPl0KPj4Kc3RhcnR4cmVmCjg2MTgKJSVFT0YK"

const ocrPNGB64 = "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"

// ── helpers ────────────────────────────────────────────────────────────────

// needOCR skips when this machine cannot OCR, and says WHICH of the two reasons
// it is — because the difference is the thing under test and a skip line that
// blurs it would hide a regression in the very code that draws it.
func needOCR(t *testing.T) {
	t.Helper()
	ok, _, why := probePrepToolDetail(prepTool{
		Name: "ocr", Bin: "tesseract", Args: []string{"--version"}, Prove: ocrProve})
	if !ok {
		if why != "" {
			t.Skip("this machine cannot OCR: " + why)
		}
		t.Skip("tesseract is not installed on this machine")
	}
}

func needPDFOCR(t *testing.T) {
	t.Helper()
	needOCR(t)
	if _, err := runCmd(5*time.Second, "pdftoppm", "-v"); err != nil {
		t.Skip("pdftoppm (poppler) is not installed on this machine")
	}
}

func extractResp(t *testing.T, out string) ctxExtractResp {
	t.Helper()
	var r ctxExtractResp
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("reply is not a ctx_extract result: %v\n%s", err, out)
	}
	return r
}

// ── the measurement that decides the probe ─────────────────────────────────

// THE WHOLE REASON contextocr.go DOES NOT PROBE WITH --version.
//
// tesseract ships its engine and its language data as separate packages on every
// distro that packages it (Ubuntu: tesseract-ocr and tesseract-ocr-eng; verified
// with dpkg -L, the base package contains no .traineddata at all). This asserts
// the consequence, against the real binary, by pointing TESSDATA_PREFIX at an
// empty directory:
//
//	--version    exits 0   <- a probe that believed this advertises OCR on a
//	                          machine that cannot read one word
//	a real OCR   exits 1   <- the only authority for the capability
//
// If a future tesseract ever makes --version fail without language data, this
// test goes red and contextocr.go's header becomes wrong — which is the point.
// It is a measurement, pinned, not a comment anyone has to trust.
func TestVersionExitCodeIsNotEvidenceOfLanguageData(t *testing.T) {
	needOCR(t)
	empty := t.TempDir()
	t.Setenv("TESSDATA_PREFIX", empty)

	if _, err := runCmd(10*time.Second, "tesseract", "--version"); err != nil {
		t.Fatalf("tesseract --version failed with no language data (%v) — if this is "+
			"now the behaviour, contextocr.go's header and its real-OCR probe are "+
			"describing a version of tesseract that no longer exists", err)
	}
	// And --list-langs, the other obvious cheap probe, also exits 0.
	if _, err := runCmd(10*time.Second, "tesseract", "--list-langs"); err != nil {
		t.Fatalf("tesseract --list-langs failed with no language data (%v) — same "+
			"note as above", err)
	}
	// The real thing does not.
	img := filepath.Join(t.TempDir(), "probe.png")
	if err := os.WriteFile(img, ocrProbePNG, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(20*time.Second, "tesseract", img, "-", "--psm", ocrProbePSM); err == nil {
		t.Fatal("tesseract OCR'd an image with NO language data available — the " +
			"empty TESSDATA_PREFIX did not take effect, so this test is not " +
			"measuring what it claims to")
	}
}

// A box with the engine and no language data must be BLOCKED-with-a-reason, not
// silently absent. Those two are the same empty tool list to the host, they are
// fixed by different commands, and telling a user "no machine of yours can OCR"
// when tesseract is sitting on their disk sends them to install it twice.
func TestNoLanguageDataReportsWhyRatherThanNothing(t *testing.T) {
	needOCR(t)
	t.Setenv("TESSDATA_PREFIX", t.TempDir())

	ok, _, why := probePrepToolDetail(prepTool{
		Name: "ocr", Bin: "tesseract", Args: []string{"--version"}, Prove: ocrProve})
	if ok {
		t.Fatal("a machine with no language data was advertised as able to OCR")
	}
	if why == "" {
		t.Fatal("a machine with tesseract installed and no language data reported " +
			"NOTHING — indistinguishable from a machine with no tesseract, which " +
			"is the distinction this lane is required to make")
	}
	if !strings.Contains(strings.ToLower(why), "language") {
		t.Fatalf("the reason does not name the missing piece: %q", why)
	}
	// And it must reach the host: the scan report is where the distinction
	// travels, and a reason that never leaves the box is not a distinction.
	resetPrepCache()
	_, scan := scanPrepTools()
	found := false
	for _, b := range scan.Blocked {
		if b.Name == "ocr" && strings.Contains(strings.ToLower(b.Reason), "language") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the blocked reason never made it into the scan report: %+v", scan.Blocked)
	}
	resetPrepCache()
}

// osd is orientation/script detection. It ships INSIDE the base engine package
// and it cannot recognise a word. Counting it as a language would rebuild the
// exact bug above: a box with the engine and no language pack would report one
// language and still OCR nothing.
func TestOSDIsNotCountedAsALanguage(t *testing.T) {
	needOCR(t)
	for _, l := range ocrLangs() {
		if l == ocrLangOSD {
			t.Fatal("osd is being reported as a recognition language — a machine " +
				"with only osd.traineddata would look language-equipped and read nothing")
		}
	}
	if ocrLang() == ocrLangOSD {
		t.Fatal("the box would try to OCR with osd")
	}
}

// ── end to end: a real image ───────────────────────────────────────────────

// THE ACCEPTANCE TEST. A real PNG of known words, base64 into a real
// ctx_extract frame, through the real caps gate, out to real tesseract, and the
// words come back.
func TestOCRReadsARealImageThroughTheFrame(t *testing.T) {
	setupBox(t)
	needOCR(t)
	resetPrepCache()

	out, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "ocr", ocrPNGB64)})
	if code != 0 {
		t.Fatalf("ctx_extract ocr failed: %d %s", code, errOut)
	}
	r := extractResp(t, out)
	if !strings.Contains(r.Text, ocrFixtureLine1) {
		t.Fatalf("OCR did not return the words on the image.\nwant a line containing %q\ngot:\n%s",
			ocrFixtureLine1, r.Text)
	}
	if !strings.Contains(r.Text, ocrFixtureLine2) {
		t.Fatalf("OCR read only the top of the image — the second line is missing:\n%s", r.Text)
	}
	if r.Tool != "ocr" {
		t.Fatalf("the reply names the wrong job: %q", r.Tool)
	}
	if r.Lang == "" {
		t.Fatal("the reply does not say which language the engine read in — a wrong " +
			"transcription then has no visible first thing to check")
	}
}

// ── end to end: a real SCANNED PDF ─────────────────────────────────────────

// THE NAMED CASE, and the outcome named as the worst one.
//
// First: prove the premise rather than assert it. pdf-text on this document
// succeeds and returns NOTHING — a user whose scanned contract went down that
// path would be told, by a job that exited 0, that their document has no words
// on it.
func TestPDFTextReturnsNothingForAScannedDocument(t *testing.T) {
	setupBox(t)
	if _, err := runCmd(5*time.Second, "pdftotext", "-v"); err != nil {
		t.Skip("pdftotext is not installed on this machine")
	}
	resetPrepCache()

	out, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-text", scannedPDFB64)})
	if code != 0 {
		t.Fatalf("pdf-text refused the scanned PDF (%d %s) — this fixture is supposed "+
			"to be a VALID pdf that simply has no text layer", code, errOut)
	}
	r := extractResp(t, out)
	if strings.TrimSpace(strings.ReplaceAll(r.Text, "\f", "")) != "" {
		t.Fatalf("the scanned fixture has a text layer after all (%q) — it is not a "+
			"scanned document and every test below it is measuring the wrong thing", r.Text)
	}
}

// And then the fix: the same bytes, asked for by the job that OCRs, come back
// as the words that are visibly on the page.
func TestPDFOCRReadsAScannedDocument(t *testing.T) {
	setupBox(t)
	needPDFOCR(t)
	resetPrepCache()

	out, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-ocr", scannedPDFB64)})
	if code != 0 {
		t.Fatalf("ctx_extract pdf-ocr failed: %d %s", code, errOut)
	}
	r := extractResp(t, out)
	if !strings.Contains(r.Text, ocrFixtureLine1) {
		t.Fatalf("a scanned PDF came back without the words on it.\nwant %q\ngot:\n%s",
			ocrFixtureLine1, r.Text)
	}
	// BOTH pages, so the loop is not stopping after the first.
	if strings.Count(r.Text, ocrFixtureLine2) < 2 {
		t.Fatalf("only one page of a two-page scan was read:\n%s", r.Text)
	}
	if r.Pages != 2 {
		t.Fatalf("pages=%d, want 2 — the reply must say how much of the document it read", r.Pages)
	}
	if r.PagesOCR != 2 {
		t.Fatalf("pages_ocr=%d, want 2 — both pages of this document have no text "+
			"layer, so both must be recorded as engine-read", r.PagesOCR)
	}
	if r.PagesMore {
		t.Fatal("a two-page document was reported as having more pages than the cap")
	}
	if r.Deadline {
		t.Fatal("a two-page document ran out of time — the budget arithmetic is wrong")
	}
}

// A PDF THAT ALREADY HAS TEXT comes back as its own text, not as a
// transcription of a picture of it. pdf-ocr's contract is "the text layer where
// there is one, the engine where there is not".
//
// NOTE WHAT THIS FIXTURE IS AND IS NOT. Its single page carries 44 characters,
// which is INSIDE ocrPageHasText's band, so this page does reach the engine for
// a second opinion — the widened band admits it deliberately. What the
// test pins is the outcome: the engine's reading is not a multiple longer than
// the page's own 44 characters, so the document's text is what is kept and
// pages_ocr stays 0. The case where a text page is never rendered at all is a
// DIFFERENT one and is pinned by TestATextPDFRendersNoPages, against a document
// with an ordinary page's worth of text on it.
func TestPDFOCRUsesTheTextLayerWhenThereIsOne(t *testing.T) {
	setupBox(t)
	needPDFOCR(t)
	resetPrepCache()

	out, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-ocr", probePDFB64)})
	if code != 0 {
		t.Fatalf("ctx_extract pdf-ocr failed on a text PDF: %d %s", code, errOut)
	}
	r := extractResp(t, out)
	if !strings.Contains(r.Text, probePDFText) {
		t.Fatalf("the text layer was not returned:\n%s", r.Text)
	}
	if r.PagesOCR != 0 {
		t.Fatalf("pages_ocr=%d on a document whose every page has a text layer — the "+
			"engine ran when it had nothing to add", r.PagesOCR)
	}
	if r.Pages != 1 {
		t.Fatalf("pages=%d, want 1", r.Pages)
	}
}

// A BLANK PAGE IS NOT A MISSING CAPABILITY. The third of the three answers: the
// engine ran, it read every page, and the pages are empty. That has to come back
// as a successful job that read N pages, not as a refusal and not as silence —
// otherwise it is indistinguishable from a box with no OCR.
func TestABlankScanReportsPagesReadNotAFailure(t *testing.T) {
	setupBox(t)
	needPDFOCR(t)
	resetPrepCache()

	blank := makeBlankScannedPDF(t)
	out, errOut, code := driveExtract(t, tAnchor, []string{extractReq(t, "pdf-ocr", blank)})
	if code != 0 {
		t.Fatalf("a blank scanned page was reported as a FAILED job (%d %s) — it is a "+
			"successful reading of a page with nothing on it", code, errOut)
	}
	r := extractResp(t, out)
	if strings.TrimSpace(r.Text) != "" {
		t.Fatalf("the engine invented text on a blank page: %q", r.Text)
	}
	if r.Pages < 1 || r.PagesOCR < 1 {
		t.Fatalf("a blank scan reported pages=%d pages_ocr=%d — with both at zero this "+
			"is the same reply a box with no engine gives, which is the distinction "+
			"this lane exists to make", r.Pages, r.PagesOCR)
	}
}

// makeBlankScannedPDF is a one-page PDF with a single white image on it and no
// text layer — built here rather than embedded, because it is 3 lines of PDF and
// a fixture nobody can regenerate is worse than one that costs nothing.
func makeBlankScannedPDF(t *testing.T) string {
	t.Helper()
	// A 2x2 white 8-bit grayscale image, uncompressed, drawn across the page.
	pdf := "%PDF-1.4\n" +
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] " +
		"/Resources << /XObject << /Im0 5 0 R >> >> /Contents 4 0 R >>\nendobj\n" +
		"4 0 obj\n<< /Length 42 >>\nstream\nq 200 0 0 200 0 0 cm /Im0 Do Q\nendstream\nendobj\n" +
		"5 0 obj\n<< /Type /XObject /Subtype /Image /Width 2 /Height 2 " +
		"/ColorSpace /DeviceGray /BitsPerComponent 8 /Length 4 >>\nstream\n" +
		"\xff\xff\xff\xff\nendstream\nendobj\n" +
		"trailer\n<< /Size 6 /Root 1 0 R >>\n%%EOF\n"
	return base64.StdEncoding.EncodeToString([]byte(pdf))
}

// ── the cap, and the promise that it is never silent ───────────────────────

// A document longer than one job reads must SAY SO. Silently returning 30 pages
// of a 44-page contract is the same failure as returning an empty scan: the user
// has no way to know the rest exists.
//
// Driven at cap=1 against the real two-page scan rather than by building a
// 31-page one: the cap is the only variable, every other decision in the run is
// the one production takes, and the alternative costs 31 real OCR passes to
// assert one boolean.
func TestPageCapIsReportedNeverSilent(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "scan.pdf")
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scannedPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	text, pages, total, deadline, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 1)
	if err != nil {
		t.Fatalf("pdf-ocr failed: %v", err)
	}
	if deadline {
		t.Fatal("one page ran out of 150 s")
	}
	if len(pages) != 1 {
		t.Fatalf("read %d pages with the cap at 1", len(pages))
	}
	if total >= 0 {
		t.Fatal("a document with a page past the cap was reported as complete — the " +
			"user would have no way to know the rest of their document exists")
	}
	if !strings.Contains(text, ocrFixtureLine1) {
		t.Fatalf("the one page it did read came back without its words:\n%s", text)
	}
	// And the page past the cap must not leak into the text: it was rendered to
	// answer "is there more" and OCRing it would return content from a page this
	// job is not claiming to have done.
	if strings.Count(text, ocrFixtureLine2) != 1 {
		t.Fatalf("page 2 was read despite the cap of 1:\n%s", text)
	}
	// A document SHORTER than the cap is reported complete, from the same run.
	_, _, total2, _, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 5)
	if err != nil {
		t.Fatal(err)
	}
	if total2 != 2 {
		t.Fatalf("a 2-page document under a cap of 5 reported total=%d, want 2", total2)
	}
	// Nothing of the user's document is left behind.
	left, _ := os.ReadDir(dir)
	for _, e := range left {
		if strings.HasPrefix(e.Name(), "ocrpages-") {
			t.Fatalf("the rasterized pages of the user's document were left on disk: %s", e.Name())
		}
	}
}

// THE MECHANISM, asserted cheaply against both binaries that carry it.
//
// pdf-ocr asks for ONE PAGE MORE than it will read and uses the existence of
// that page as the answer to "is there more". That request now rides the TEXT
// LAYER pass, which costs 6 ms instead of the ~490 ms a rendered page costs, so
// the properties the count depends on are pdftotext's: -l bounds it, asking past
// the end is not an error, and every real page produces exactly one form feed —
// for a scanned document too, whose pages are form feeds and nothing else.
//
// The render probe keeps its own half of this, because it is still what answers
// the count when the layer pass will not (renderPageProbe). Both are driven here
// against the real binaries and the real fixture.
func TestPageCapMechanismAsksForOneMorePage(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "scan.pdf")
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scannedPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// THE LAYER PASS, which is where the count comes from now. Asked for 1+1
	// pages of a 2-page document it must answer 2 — and asked for far more than
	// the document has it must still answer 2 and still exit 0, which is what
	// makes one request serve both "how many" and "is there more".
	for _, ask := range []int{2, 31} {
		got, ok := pdfTextByPage(src, ask, time.Now().Add(60*time.Second))
		if !ok {
			t.Fatalf("the layer pass refused a valid scanned document when asked for %d pages", ask)
		}
		if len(got) != 2 {
			t.Fatalf("pdftotext -f 1 -l %d reported %d pages of a 2-page scan, want 2 — "+
				"the page count rides the form feeds of this pass", ask, len(got))
		}
	}
	// A scanned page really does produce a form feed and no characters, which is
	// the property that lets the count come from a document with no text at all.
	if layer, _ := pdfTextByPage(src, 31, time.Now().Add(60*time.Second)); strings.TrimSpace(layer[0]) != "" {
		t.Fatalf("the scanned fixture's first page has text (%q) — the count and the "+
			"per-page decision would be reading the same thing", layer[0])
	}

	// THE RENDER PROBE, the fallback half: same cap+1 bound, and the page past
	// the cap is removed before anything can read it.
	pages, more, err := renderPageProbe(dir, src, 1, time.Now().Add(60*time.Second))
	if err != nil {
		t.Fatalf("the render probe refused the fixture: %v", err)
	}
	if !more || len(pages) != 1 {
		t.Fatalf("the render probe returned %d page(s), more=%v, want 1 and true", len(pages), more)
	}
	left, _ := filepath.Glob(filepath.Join(dir, "probe-*.png"))
	if len(left) != 1 {
		t.Fatalf("%d rendered pages are on disk after a cap of 1 — the page past the "+
			"cap exists only to answer \"is there more\" and OCRing it would return "+
			"text from a page this job is not claiming to have done", len(left))
	}
	// And past the end it produces nothing, which is how a document SHORTER than
	// the cap is correctly reported as complete.
	if _, moreThan5, err := renderPageProbe(dir, src, 5, time.Now().Add(60*time.Second)); err != nil || moreThan5 {
		t.Fatalf("a 2-page document under a cap of 5 reported more=%v (err=%v) — the "+
			"more-pages signal would fire on every document", moreThan5, err)
	}
}

// ── budgets ────────────────────────────────────────────────────────────────

// The ceiling is DERIVED from the page cap and the measured per-page cost, not
// chosen beside it. If someone raises the cap without touching the budget the
// arithmetic still holds; if someone replaces the formula with a literal, this
// is what notices.
func TestOCRTimeoutIsDerivedFromThePageCap(t *testing.T) {
	want := ocrSetupBudget + ocrPageCap*ocrPerPageBudget
	if ocrExtractTimeout != want {
		t.Fatalf("ocrExtractTimeout is %s but the page cap and per-page budget say %s — "+
			"a job can now be cut off mid-document by a number nobody re-derived",
			ocrExtractTimeout, want)
	}
	// And every OCR job must get more time than the default, or the whole point
	// of a per-tool ceiling is lost.
	if ctxExtractTimeoutFor("pdf-ocr") <= ctxExtractTimeout {
		t.Fatal("pdf-ocr gets no more time than pdf-text — every scanned document " +
			"over a few pages would be cut off")
	}
	if ctxExtractTimeoutFor("ocr") <= 0 {
		t.Fatal("ocr has no ceiling")
	}
	if ctxExtractTimeoutFor("pdf-text") != ctxExtractTimeout {
		t.Fatal("the default ceiling moved — the host mirrors it and would now give up first")
	}
}

// The advertised OCR jobs must carry the language list, because "which pack is
// my machine using" is the first question a wrong transcription raises and the
// answer must not require running anything.
func TestOCRToolsAdvertiseTheirLanguages(t *testing.T) {
	setupBox(t)
	needOCR(t)
	resetPrepCache()

	tools, _, ok := prepCapable(tAnchor)
	if !ok {
		t.Skip("no prep tools on this machine")
	}
	for _, name := range []string{"ocr", "pdf-ocr"} {
		for _, tool := range tools {
			if tool.Name != name {
				continue
			}
			if len(tool.Langs) == 0 {
				t.Fatalf("%s is advertised with no language list", name)
			}
			for _, l := range tool.Langs {
				if l == ocrLangOSD {
					t.Fatalf("%s advertises osd as a language", name)
				}
			}
		}
	}
	resetPrepCache()
}

// ── the budget, which is why there is no table on the host ─────────────────

// EVERY ADVERTISED JOB MUST DECLARE WHAT IT COSTS, because the host's dispatch
// wait is built from that declaration and nothing else. A job advertised with no
// ceiling would arrive at the host as 0 and fall to the host's guard value,
// which is the text-layer number — and a job worth advertising is rarely a job
// that finishes in twenty seconds.
//
// This is the gate that makes the design safe for tools that do not exist yet:
// the speech-to-text and video-frame lanes being built alongside this one cannot
// ship a job whose cost the host has to guess.
func TestEveryAdvertisedToolDeclaresItsCeiling(t *testing.T) {
	setupBox(t)
	resetPrepCache()
	defer resetPrepCache()

	tools, _, _ := prepCapable(tAnchor)
	if len(tools) == 0 {
		t.Skip("no prep tools installed on this machine")
	}
	for _, tool := range tools {
		if tool.CeilingS <= 0 {
			t.Fatalf("%q is advertised with no ceiling — the host builds its dispatch "+
				"wait from this number, so a job without one is a job the host has to "+
				"guess the cost of", tool.Name)
		}
		// DECLARED == ENFORCED. Two literals would be the mirror again, one file
		// closer. The advertisement must be read from the same function the job
		// is actually run under.
		if want := ctxExtractTimeoutFor(tool.Name).Seconds(); tool.CeilingS != want {
			t.Fatalf("%q advertises %.0fs but is RUN under %.0fs — the declaration and "+
				"the enforcement have to be one value", tool.Name, tool.CeilingS, want)
		}
	}
}

// THE GRANT IS CLAMPED DOWN, NEVER UP — the same rule ctxPullBudget follows, for
// the same reason: the host's wait is the grant plus a round trip, so a box that
// took a grant LARGER than its own ceiling would be working past the moment the
// host gave up, and a box that let the host raise its ceiling could be parked by
// a host for as long as that host liked.
func TestExtractBudgetClampsDownNeverUp(t *testing.T) {
	own := ctxExtractTimeoutFor("pdf-ocr")

	if got := ctxExtractBudget("pdf-ocr", own.Seconds()*10); got != own {
		t.Fatalf("a host granting 10x got %s, want this box's own %s — a grant must "+
			"never RAISE what this machine will spend", got, own)
	}
	if got := ctxExtractBudget("pdf-ocr", 5); got != 5*time.Second {
		t.Fatalf("a grant below the box's ceiling was ignored: got %s, want 5s", got)
	}
	// A HOST THAT PREDATES THE FIELD still works. It can only be asking for the
	// text-layer read, and refusing would break every bastion whose host has not
	// been updated.
	if got := ctxExtractBudget("pdf-text", 0); got != ctxExtractTimeout {
		t.Fatalf("a job from a host with no grant got %s, want the box's own %s",
			got, ctxExtractTimeout)
	}
	if got := ctxExtractBudget("pdf-text", -17); got != ctxExtractTimeout {
		t.Fatalf("a negative grant must fall back to the box's own ceiling, got %s", got)
	}
}

// AND THE GRANTED NUMBER REACHES THE RUNNER, proved end to end through a real
// frame rather than by arithmetic that nothing calls.
//
// The proof is the box's own timeout sentence: it names the duration the job was
// actually run under, so granting an absurdly small budget and reading that
// number back is a direct observation of the wire field arriving, being clamped,
// and bounding the work. Deterministic at 1 ms — no machine rasterizes and reads
// a page in a millisecond — where a "grant less than it needs" test against a
// small fixture would be a race (this fixture's whole pipeline measures 0.31 s).
func TestGrantedBudgetBoundsARealJob(t *testing.T) {
	setupBox(t)
	if _, err := runCmd(5*time.Second, "pdftotext", "-v"); err != nil {
		t.Skip("pdftotext is not installed on this machine")
	}
	resetPrepCache()

	req, err := json.Marshal(ctxExtractReq{
		Tool: "pdf-text", Mime: "application/pdf",
		B64: strings.Join(strings.Fields(probePDFB64), ""), ExtractBudget: 0.001})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	out, errOut, code := driveExtract(t, tAnchor, []string{string(req)})
	elapsed := time.Since(start)

	if code == 0 {
		t.Fatalf("a job granted 1 ms returned a complete result in %s — the grant "+
			"never reached the runner:\n%s", elapsed, out)
	}
	if !strings.Contains(errOut, "1ms") {
		t.Fatalf("the job was bounded by something OTHER than the granted 1 ms — the "+
			"box reports the duration it actually ran under, and it is not the grant:\n%s",
			errOut)
	}
	// And it is a DEADLINE, not a rejected document: the two were being reported
	// as one, and the difference is whether the user goes looking at their file.
	if !strings.Contains(errOut, "still working") {
		t.Fatalf("running out of the granted time was reported as a bad document:\n%s", errOut)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("a job granted 1 ms took %s to come back", elapsed)
	}
}

// The other direction, on the same path: a NORMAL grant — the one the host
// actually sends, this box's own declared ceiling — runs the job to completion.
// Without this the test above passes on a build where the grant is always tiny.
func TestDeclaredCeilingAsAGrantRunsTheJob(t *testing.T) {
	setupBox(t)
	needPDFOCR(t)
	resetPrepCache()

	// Exactly what the host does: read the box's declared ceiling out of the
	// advertisement and hand that number back in the job.
	tools, _, _ := prepCapable(tAnchor)
	var declared float64
	for _, tool := range tools {
		if tool.Name == "pdf-ocr" {
			declared = tool.CeilingS
		}
	}
	if declared <= 0 {
		t.Fatal("pdf-ocr is advertised with no ceiling for the host to grant")
	}
	req, err := json.Marshal(ctxExtractReq{
		Tool: "pdf-ocr", Mime: "application/pdf",
		B64: strings.Join(strings.Fields(scannedPDFB64), ""), ExtractBudget: declared})
	if err != nil {
		t.Fatal(err)
	}
	out, errOut, code := driveExtract(t, tAnchor, []string{string(req)})
	if code != 0 {
		t.Fatalf("the job failed under the grant the host would actually send "+
			"(%.0fs): %d %s", declared, code, errOut)
	}
	r := extractResp(t, out)
	if strings.Count(r.Text, ocrFixtureLine2) < 2 || r.Deadline {
		t.Fatalf("the document came back incomplete under a full grant "+
			"(deadline=%v):\n%s", r.Deadline, r.Text)
	}
}

// ── the comparison the comment promised ────────────────────────────────────

// mixedLayerPDF is a one-page PDF carrying BOTH a short real text layer and a
// picture of a different word, which is the exact shape the defect lives in.
//
// Built here rather than embedded because every byte of it is derived: the
// picture IS ocrProbePNG, the same image the capability probe reads, decoded to
// grayscale samples and flated into an image XObject; the text layer is thirteen
// characters drawn in PDF text render mode 3, which is the invisible-text mode a
// scanner's own OCR layer uses.
//
// The numbers are what make it a test rather than an illustration:
//
//	text layer   "REF 4471-XQ99"   13 chars  <- under ocrPageHasText (16), so
//	                                            the page goes to the engine
//	OCR          "PRIVATAE"         8 chars  <- non-empty, and FEWER
//
// Measured through the real binaries before it was written down: pdftotext
// returns exactly those 13 characters and tesseract reads exactly that word.
// Under the old code the 8 were kept and the 13 thrown away, with the page
// recorded as pages_ocr=1 as though a choice had been made.
func mixedLayerPDF(t *testing.T) string {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(ocrProbePNG))
	if err != nil {
		t.Fatalf("the embedded probe image does not decode: %v", err)
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	gray := make([]byte, 0, w*h)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, _ := img.At(x, y).RGBA()
			gray = append(gray, byte((r*299+g*587+bl*114)/1000>>8))
		}
	}
	var zb bytes.Buffer
	zw := zlib.NewWriter(&zb)
	if _, err := zw.Write(gray); err != nil {
		t.Fatal(err)
	}
	zw.Close()

	content := fmt.Sprintf("q 360 0 0 88 20 60 cm /Im0 Do Q\nBT /F1 10 Tf 3 Tr 20 20 Td (%s) Tj ET\n",
		mixedLayerText)
	objs := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 400 200] /Resources " +
			"<< /XObject << /Im0 5 0 R >> /Font << /F1 6 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
		fmt.Sprintf("<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace "+
			"/DeviceGray /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream",
			w, h, zb.Len(), zb.String()),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}
	var pdf bytes.Buffer
	pdf.WriteString("%PDF-1.4\n")
	offs := make([]int, 0, len(objs))
	for i, o := range objs {
		offs = append(offs, pdf.Len())
		fmt.Fprintf(&pdf, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := pdf.Len()
	fmt.Fprintf(&pdf, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, o := range offs {
		fmt.Fprintf(&pdf, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&pdf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(objs)+1, xref)
	return base64.StdEncoding.EncodeToString(pdf.Bytes())
}

// The thirteen characters of the text layer, and the word the picture says.
const mixedLayerText = "REF 4471-XQ99"

// THE ASSERTION: the engine's output is kept only when it found MORE than
// the text layer did. That sentence was in this lane's source as a promise, and
// the code kept the engine's output whenever it was non-empty, comparing
// nothing. A page with a short real reference code and a picture the engine
// reads badly would lose the code — real characters of the user's document,
// thrown away for a worse guess, with the record saying a page was OCR'd.
func TestOCRIsKeptOnlyWhenItBeatsTheTextLayer(t *testing.T) {
	needPDFOCR(t)
	if len(mixedLayerText) != 13 {
		t.Fatalf("the fixture's text layer is %d chars; the test needs it under "+
			"ocrPageHasText (%d) and longer than the word the picture says",
			len(mixedLayerText), ocrPageHasText)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "mixed.pdf")
	raw, err := base64.StdEncoding.DecodeString(mixedLayerPDF(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// The two sides, measured through the real binaries rather than assumed, so
	// a failure below says which half moved.
	layer, layerRead := pdfTextByPage(src, 1, time.Now().Add(30*time.Second))
	if !layerRead || len(layer) == 0 || strings.TrimSpace(layer[0]) != mixedLayerText {
		t.Skipf("this poppler does not read the fixture's invisible text layer as %q "+
			"(got %q, read=%v) — the fixture, not the code, is what changed",
			mixedLayerText, layer, layerRead)
	}

	text, pages, _, deadline, err := runPDFOCRCapped(dir, src,
		time.Now().Add(ocrExtractTimeout), 1)
	if err != nil {
		t.Fatalf("pdf-ocr failed on the mixed page: %v", err)
	}
	if deadline {
		t.Fatal("one page ran out of time")
	}
	if len(pages) != 1 {
		t.Fatalf("read %d pages, want 1", len(pages))
	}
	if !strings.Contains(text, mixedLayerText) {
		t.Fatalf("the engine's shorter reading REPLACED the page's real text layer.\n"+
			"  the document states %q (%d chars)\n"+
			"  what was kept instead: %q\n"+
			"pdf-ocr's contract is that OCR is kept only when it found MORE than the "+
			"text layer did; the user's own characters were discarded for the engine's "+
			"guess", mixedLayerText, len(mixedLayerText), strings.TrimSpace(text))
	}
	if pages[0].How != "text" {
		t.Fatalf("the page was recorded as how=%q after the text layer won — the "+
			"record has to say which of the two was actually kept", pages[0].How)
	}
}

// THE OTHER DIRECTION, from the same mechanism: where the engine DOES find more
// than the text layer, its reading is what is kept. A comparison that always
// preferred the layer would silently turn pdf-ocr back into pdf-text.
func TestOCRStillWinsWhenItFindsMoreThanTheLayer(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "scan.pdf")
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scannedPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	text, pages, _, _, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, ocrFixtureLine1) {
		t.Fatalf("a scan with no text layer came back without its words:\n%s", text)
	}
	for _, p := range pages {
		if p.How != "ocr" {
			t.Fatalf("page %d of a document with NO text layer was recorded as how=%q",
				p.Page, p.How)
		}
	}
}

// ── the rotated scan ───────────────────────────────────────────────────────

// A real image-only PDF of a six-line letter page, SCANNED UPSIDE DOWN. Its text
// layer is exactly zero characters, so every page of it goes to the engine.
//
// Regenerate with the two published commands and nothing else — the -dAutoRotate
// Pages=/None matters, because without it ps2pdf quietly turns the page the right
// way up again and the fixture stops testing anything:
//
//	ps2pdf -dAutoRotatePages=/None rot.ps rot.pdf
//	gs -q -dNOPAUSE -dBATCH -sDEVICE=pdfimage8 -r100 -sOutputFile=rotscan.pdf rot.pdf
//
// where rot.ps draws the six lines below after `306 396 translate 180 rotate
// -306 -396 translate`.
//
// MEASURED at 300 dpi: the default page-segmentation mode reads it as
// "'y yBnoswuy) ind sem yeu] JusuNDOP Bul", and --psm 1 reads it exactly.
const rotatedScanPDFB64 = "" +
	"JVBERi0xLjMKJcfsj6IKJSVJbnZvY2F0aW9uOiBncyAtcSAtZE5PUEFVU0UgLWRCQVRDSCAtc0RFVklDRT1wZGZpbWFnZTggLXIx" +
	"MDAgLXNPdXRwdXRGaWxlPT8gPwo0IDAgb2JqCjw8Ci9MZW5ndGggNSAwIFIKL1N1YnR5cGUgL0ltYWdlCi9XaWR0aCA4MjYKL0hl" +
	"aWdodCAxMTY5Ci9Db2xvclNwYWNlIC9EZXZpY2VHcmF5Ci9CaXRzUGVyQ29tcG9uZW50IDgKL0ZpbHRlciAvRmxhdGVEZWNvZGUK" +
	"Pj4Kc3RyZWFtCnic7dzRdqO4EgVQ/v+nde8kMVSVShg77kymvfdDGoOQRC8dg2zDGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
	"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" +
	"Dh9vv2V+EpPTzXPiA2zn5Gyp2rTh9na/jWbPKTnbVMd8tZZ7Hmo/OlGO8e7Td/PMq8YizpYk572loTbGnoflOWd/zz7ek5tzTrch" +
	"pOrSOacNV0rO1PPpgLZcMnX+pKPzmbHWKDnvrg6/2+i8mJzyDnx3njP2FyMX6JLTvb1PFe+NlpexrXDOmJJzr6PN/5HkMMZoxu1y" +
	"PN8itV/KrK5d2g37qy5zd/eckjNSl3Lt+VhyyXQdNp3DSvmT/x3JeXPlK5D9b/tNRh58W9h7ni9NG8LLWP80Oo9JSVkqi/NCPZi5" +
	"ZOr8qqO1wv77nHzIkvN+0oDP6+OAWJQa+xCrJW5XP2XDMdZWzYYtcXzPHdnmuppZTi7Zt7guPx3UlneUHFqXB8RyZJ4M2ZeU/5dJ" +
	"Dq1XJudaJv4TyZkP6r/Qa36Q5LTSQW2Hf7NPAAAAAAAAAAAAPOo1v/vy6zHezGt+Mel3l7wZZxx4huTAKE8dSHf1xxut6w7lVv/p" +
	"2QX5sQX5iQK12eM+71vxo1DqSH4mx0fBucD0cIJ5ldDyAvGhHeP27IyRR3/zzIAy2tPCKjnzUw66XMSHGoypspycrrW5P6v64Rvq" +
	"uBvjeLDO7RSQkhOfX5XCtu82j+U5OekpWGnY15tTT5NTepqXmo1Hc/A9x4CKz9EdOTl5zKdXzYCe0/jZyFzLdGLqPnJ7MDlHx/LC" +
	"/EBr+Ia7yQkFxnFSKDOUfd1RZ0nOtq1r2XfKyTnauJOc7Tw5oa9mObzK/eTUtXHNbbTfxmM389hPONs21ZJyMuqa3JGnzzl5lezw" +
	"EvfmOc2kvexSJidTgTk5pZawcvzZec7RRfie6ZPlsZ9IriZnLjmP4G2vPO2WPhvYQvmj2P3kzAVCPc1G5xy+LV7+f46sbdtGmBWE" +
	"d+7wb9wlBSavulU6Yi76WuJ8Jp508vcwc3LmAmNeaJfgG9Ig/fw3vbq48/G2vpXtd+uJWTtrY54Rja/LxG0q0Kxr64HXeXJc3R35" +
	"rzTnAf5taSxeH5nbYr+Xj+3uEwL4ZSQHAAAAAAAAAACAx/hlFzzB3SjwBLmBZ0gONDfTN4+tuD1a7HZTdNn7eLxGvll/v/v4KB7u" +
	"gomdGKGJ5jac2H6pILU0Rmmy3nqdb8suvZ1qLv2oh136OHgny+e81FVbKJyGUChbh3ZdyPePxV6k/syJi+VyBbVL15Nze79outFU" +
	"kjbHRiXnTXXJWTzcbNwGaxnoMTnHuhHG0kuTk8d3LZrDOj3Go/b8yeSkNprj4W1saWlOQszE+ql/OTnzVdfyPXqRnL6bsYI5MXNF" +
	"bXJOu7FKTHtckvOejiv8eK3/NdtIV2tl2233o0QZqWnALqcpdTnNO+bexsIXkjN3JHd80Y1wWTZPfySHfxxvq/ENtvmsYIt7XEhO" +
	"GvfdtdNpcqYaUudCR5bJGd0HGg8npytaqlufIfmbLS7I5nNO2mGbx1adKuWBdJwstkN4Vfuz/9lXp4+z1mewdKJLPS6fwaUd+pNL" +
	"7UefnPUZkr9Zm5wuCanYheTMzTTv4HsWlv0p1cQa7p9zYpVl86VzTn3TmPZwznljcQIT38jjO3Xa+LnXvvft73JeNGKJKTkjVXcl" +
	"OW0Ff+ZqbZGcfrPkvJ3mEmYcQ/jIyPn1yJ2rlW3P3JXkhHlXreVqcpqs1s2l6TZ+5UWuT3KYPXrdfi857Xfu6+T0Ob2enMWUa2ro" +
	"XnLSibPu2vaAN/dDyckXf1eSc22eczc5t7afSs6W/pmq5p29ODn5jfpj4fNV+9larW5L5RafrcVP7WI1cca2zZXm6mMloR9ldf4k" +
	"zmdrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/OX+" +
	"ByFeI8IKZW5kc3RyZWFtCmVuZG9iago1IDAgb2JqCjM4OTUKZW5kb2JqCjYgMCBvYmoKPDwKL0ZpbHRlci9GbGF0ZURlY29kZS9M" +
	"ZW5ndGggOCAwIFIKPj4Kc3RyZWFtCnicM7U00TM3MgACBRC0MDHUM7OAc5NzufQ9cw0VXPIBnQ4INgplbmRzdHJlYW0KZW5kb2Jq" +
	"CjggMCBvYmoKMzYKZW5kb2JqCjcgMCBvYmoKPDwKL0NvbnRlbnRzIDYgMCBSCi9UeXBlIC9QYWdlCi9QYXJlbnQgMiAwIFIKL01l" +
	"ZGlhQm94IFswIDAgNTk0LjcyMDAwMCA4NDEuNjgwMDAwXQovUmVzb3VyY2VzIDw8Ci9YT2JqZWN0IDw8Ci9JbTEgNCAwIFIKPj4K" +
	"Pj4KPj4KZW5kb2JqCjEgMCBvYmoKPDwKL1BhZ2VzIDIgMCBSCi9UeXBlIC9DYXRhbG9nCi9JbmZvIDMgMCBSCj4+CmVuZG9iagoy" +
	"IDAgb2JqCjw8Ci9Db3VudCAxCi9LaWRzIFs3IDAgUiBdCi9UeXBlIC9QYWdlcwo+PgplbmRvYmoKMyAwIG9iago8PAovUHJvZHVj" +
	"ZXIoR1BMIEdob3N0c2NyaXB0IDEwLjA2LjApCi9DcmVhdGlvbkRhdGUoRDoyMDI2MDkxMzAzMzk1NFowMCcwMCcpCj4+CmVuZG9i" +
	"agp4cmVmCjAgOQowMDAwMDAwMDAwIDY1NTM2IGYgCjAwMDAwMDQ0MzggMDAwMDAgbiAKMDAwMDAwNDQ5OSAwMDAwMCBuIAowMDAw" +
	"MDA0NTU3IDAwMDAwIG4gCjAwMDAwMDAwOTUgMDAwMDAgbiAKMDAwMDAwNDE0OCAwMDAwMCBuIAowMDAwMDA0MTY4IDAwMDAwIG4g" +
	"CjAwMDAwMDQyOTQgMDAwMDAgbiAKMDAwMDAwNDI3NiAwMDAwMCBuIAp0cmFpbGVyCjw8Ci9TaXplIDkKL1Jvb3QgMSAwIFIKL0lE" +
	"IFs8QzE5ODYxNUQ2QjE5NTY0NDI4NjUwMDUyMzFGNjMzQjY+PEMxOTg2MTVENkIxOTU2NDQyODY1MDA1MjMxRjYzM0I2Pl0KPj4K" +
	"c3RhcnR4cmVmCjQ2NTIKJSVFT0YK"

// The first line of the upside-down page.
const rotatedFixtureLine1 = "ROTATED FIXTURE ALPHA zulu yankee"

// A 180-DEGREE PAGE IS STILL THE USER'S DOCUMENT. A duplex feeder puts pages
// through the other way up routinely, and before the orientation pass this lane
// wrote the engine's garbled reading of one straight into the corpus with
// nothing in the reply or the rows saying anything was wrong. Garbage that
// claims to be a document is worse than a document that says it could not be
// read.
func TestAnUpsideDownScanIsReadNotIngestedAsGarbage(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "rot.pdf")
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(rotatedScanPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// It really is a scan: no text layer at all, so nothing but the engine can
	// read it and the comparison above cannot be what makes this pass.
	if layer, _ := pdfTextByPage(src, 1, time.Now().Add(30*time.Second)); len(layer) > 0 &&
		strings.TrimSpace(layer[0]) != "" {
		t.Fatalf("the rotated fixture has a text layer (%q) — it is not a scan and "+
			"this test would prove nothing", layer[0])
	}

	text, pages, _, deadline, err := runPDFOCRCapped(dir, src,
		time.Now().Add(ocrExtractTimeout), 1)
	if err != nil {
		t.Fatalf("pdf-ocr failed on an upside-down scan: %v", err)
	}
	if deadline {
		t.Fatal("one page ran out of time")
	}
	if len(pages) != 1 {
		t.Fatalf("read %d pages, want 1", len(pages))
	}
	if !strings.Contains(text, rotatedFixtureLine1) {
		t.Fatalf("an upside-down scan went into the corpus as garbage.\n"+
			"  want the page's real words: %q\n"+
			"  what the engine returned:   %q\n"+
			"tesseract corrects this itself when it is asked to detect orientation; "+
			"without that the user's document is stored as nonsense and nothing says so",
			rotatedFixtureLine1, strings.TrimSpace(text))
	}
}

// AND THE UPRIGHT PAGE MUST NOT MOVE. The orientation pass is only worth having
// if it cannot damage the common case, so this pins the pages that read fine
// today against the exact same bytes.
func TestOrientationDetectionDoesNotChangeAnUprightPage(t *testing.T) {
	needPDFOCR(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "scan.pdf")
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(scannedPDFB64), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	text, _, _, _, err := runPDFOCRCapped(dir, src, time.Now().Add(ocrExtractTimeout), 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{ocrFixtureLine1, ocrFixtureLine2} {
		if !strings.Contains(text, want) {
			t.Fatalf("an upright scan lost %q once orientation detection was asked "+
				"for:\n%s", want, text)
		}
	}
}
