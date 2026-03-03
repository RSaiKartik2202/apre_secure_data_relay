def schnorr_signature_component(ki, e, xi, q):
    """
    Computes Schnorr signature component:
    s = (ki + e * xi) mod q
    
    Parameters:
    ki : int  -> random nonce
    e  : int  -> challenge hash value
    xi : int  -> private key
    q  : int  -> prime order of subgroup
    
    Returns:
    s  : int  -> signature component
    """
    s = (ki + (e * xi)) % q
    return s