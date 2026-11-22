"""Replace only the broken outer D with a continuous cyan-to-violet contour.
Source-dependent fixed ROI for Levencode Labs Deploom 1792 x 896 heroes.
All non-D image pixels are preserved before JPEG encoding.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter
import cv2
import numpy as np
import hashlib
import json
import sys

WIDTH, HEIGHT = 1792, 896

def cubic(p0, p1, p2, p3, n=120):
    return [((1-t)**3*p0[0]+3*(1-t)**2*t*p1[0]+3*(1-t)*t*t*p2[0]+t**3*p3[0],
             (1-t)**3*p0[1]+3*(1-t)**2*t*p1[1]+3*(1-t)*t*t*p2[1]+t**3*p3[1])
            for t in np.linspace(0, 1, n)]

PATH=[(138.5,266.5),(205,266.5)]
PATH += cubic((205,266.5),(275,266.5),(324,311),(324,381))[1:]
PATH += cubic((324,381),(324,451),(276,496),(205,496))[1:]
PATH += [(138.5,496),(138.5,266.5)]

def make_mask():
    m=np.zeros((HEIGHT,WIDTH),dtype=np.uint8)
    cv2.rectangle(m,(123,254),(149,508),255,-1)
    cv2.rectangle(m,(129,251),(215,282),255,-1)
    cv2.rectangle(m,(129,483),(215,509),255,-1)
    ys=[256,260,265,269,273,279,284,298,312,335,360,390,410,430,450,477,489,497,503]
    xs=[205,215,231,241,253,263,270,286,301,314,323,324,320,312,298,264,242,218,205]
    for y in range(253,510):
        x=np.interp(y,ys,xs)
        xl=max(199,int(round(x))-20)
        xr=min(344,int(round(x))+20)
        m[y,xl:xr+1]=255
    assert np.where(m)[1].min()>=120 and np.where(m)[1].max()<=344
    assert np.where(m)[0].min()>=251 and np.where(m)[0].max()<=509
    return m

def draw_contour(base):
    S=4
    layer=Image.new('L',(WIDTH*S,HEIGHT*S),0)
    dr=ImageDraw.Draw(layer)
    line=[(round(x*S),round(y*S)) for x,y in PATH]
    dr.line(line,fill=255,width=round(16*S),joint='curve')
    radius=8*S
    for x,y in [(138.5,266.5),(138.5,496)]:
        cx,cy=round(x*S),round(y*S)
        dr.ellipse((cx-radius,cy-radius,cx+radius,cy+radius),fill=255)
    alpha=np.asarray(layer.resize((WIDTH,HEIGHT),Image.Resampling.LANCZOS),dtype=np.float32)/255.
    x=np.arange(WIDTH,dtype=np.float32)
    t=np.clip((x-130)/202,0,1)
    stops=[(0.0,(18,219,224)),(.35,(47,166,248)),(.65,(106,117,246)),(1.0,(185,67,232))]
    colors=np.zeros((WIDTH,3),dtype=np.float32)
    for j in range(3):
        colors[:,j]=np.interp(t,[s[0] for s in stops],[s[1][j] for s in stops])
    colors=colors[None,:,:]
    out=base.astype(np.float32)
    blur=np.asarray(Image.fromarray((alpha*255).astype('uint8')).filter(
        ImageFilter.GaussianBlur(2.1)),dtype=np.float32)/255.
    halo=np.clip((blur-alpha)*.18,0,1)[:,:,None]
    out=out*(1-halo)+colors*halo
    a=alpha[:,:,None]
    out=out*(1-a)+colors*a
    return np.uint8(np.clip(np.round(out),0,255))

def patch(path,dst):
    im=Image.open(path).convert('RGB')
    assert im.size==(WIDTH,HEIGHT),f'unexpected source dimensions: {im.size}'
    before=np.asarray(im).copy()
    mask=make_mask()
    bgr=cv2.cvtColor(before,cv2.COLOR_RGB2BGR)
    restored=cv2.cvtColor(cv2.inpaint(bgr,mask,5,cv2.INPAINT_TELEA),cv2.COLOR_BGR2RGB)
    restored=np.where(mask[:,:,None]>0,restored,before)
    after=draw_contour(restored)
    changed=np.any(after!=before,axis=2)
    outside=np.ones(changed.shape,dtype=np.uint8)
    outside[239:521,109:360]=0
    assert not np.any(changed&(outside>0)), 'unexpected region modified before JPEG encoding'
    dst.parent.mkdir(parents=True,exist_ok=True)
    Image.fromarray(after).save(dst,'JPEG',quality=96,subsampling=0,optimize=True)
    report={'source_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'output_sha256':hashlib.sha256(dst.read_bytes()).hexdigest(),
            'changed_bbox_rgb_before_jpeg':
              list(Image.fromarray((changed*255).astype('uint8')).getbbox()),
            'dimensions':[WIDTH,HEIGHT]}
    return report

if __name__=='__main__':
    source=Path(sys.argv[1])
    dest=Path(sys.argv[2])
    print(json.dumps(patch(source,dest),indent=2))
