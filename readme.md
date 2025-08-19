dkg_from_coeffs
verify_share
compute_group_pk
challenge

sign:
nonces_with_params -> SignComm -> binding_and_group_comm -> challenge -> partial_z -> combine_sig

dkg:
dkg_from_coeffs -> broadcast PolyComm (open) + Share (encrypt) -> verify_share(i) -> combine_shares -> compute_group_pk


- [ ] replace assertions with Error
- [ ] encrypt Share
- [ ] investigate Pedersen commitments