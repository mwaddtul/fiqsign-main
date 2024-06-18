import streamlit as st
import datetime
from asn1crypto import cms
from dateutil.parser import parse
from pypdf import PdfReader

class AttrClass:
    def __init__(self, data, cls_name=None):
        self._data = data
        self._cls_name = cls_name

    def __getattr__(self, name):
        try:
            value = self._data[name]
        except KeyError:
            value = None
        else:
            if isinstance(value, dict):
                return AttrClass(value, cls_name=name.capitalize() or self._cls_name)
        return value

    def __values_for_str__(self):
        return [
            (k, v) for k, v in self._data.items()
            if isinstance(v, (str, int, datetime.datetime))
        ]

    def __str__(self):
        values = ", ".join([
            f"{k}={v}" for k, v in self.__values_for_str__()
        ])
        return f"{self._cls_name or self.__class__.__name__}({values})"

    def __repr__(self):
        return f"<{self}>"


class Signature(AttrClass):
    @property
    def signer_name(self):
        return (
            self._data.get('signer_name') or
            getattr(self.certificate.subject, 'common_name', '')
        )


class Subject(AttrClass):
    pass


class Certificate(AttrClass):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.subject = Subject(self._data['subject'])

    def __values_for_str__(self):
        return (
            super().__values_for_str__() +
            [('common_name', self.subject.common_name)]
        )


def parse_pkcs7_signatures(signature_data: bytes):
    content_info = cms.ContentInfo.load(signature_data).native
    if content_info['content_type'] != 'signed_data':
        return None
    content = content_info['content']
    certificates = content['certificates']
    signer_infos = content['signer_infos']
    for signer_info in signer_infos:
        sid = signer_info['sid']
        digest_algorithm = signer_info['digest_algorithm']['algorithm']
        signature_algorithm = signer_info['signature_algorithm']['algorithm']
        signature_bytes = signer_info['signature']
        signed_attrs = {
            sa['type']: sa['values'][0] for sa in signer_info['signed_attrs']}
        for cert in certificates:
            cert = cert['tbs_certificate']
            if (
                sid['serial_number'] == cert['serial_number'] and
                sid['issuer'] == cert['issuer']
            ):
                break
        else:
            raise RuntimeError(
                f"Couldn't find certificate in certificates collection: {sid}")
        yield dict(
            sid=sid,
            certificate=Certificate(cert),
            digest_algorithm=digest_algorithm,
            signature_algorithm=signature_algorithm,
            signature_bytes=signature_bytes,
            signer_info=signer_info,
            **signed_attrs,
        )

def get_pdf_signatures(filename):
    reader = PdfReader(filename)
    
    if reader.get_fields() is None:
        st.warning("No signature fields found.")
        return []

    fields = reader.get_fields().values()
    signature_field_values = [
        f.value for f in fields if f.field_type == '/Sig']
    signatures = []

    for v in signature_field_values:
        v_type = v['/Type']
        if v_type in ('/Sig', '/DocTimeStamp'):
            is_timestamp = v_type == '/DocTimeStamp'
            try:
                signing_time = parse(v['/M'][2:].strip("'").replace("'", ":"))
            except KeyError:
                signing_time = None

            raw_signature_data = v['/Contents']

            for attrdict in parse_pkcs7_signatures(raw_signature_data):
                if attrdict:
                    attrdict.update(dict(
                        type='timestamp' if is_timestamp else 'signature',
                        signer_name=v.get('/Name'),
                        signer_contact_info=v.get('/ContactInfo'),
                        signer_location=v.get('/Location'),
                        signing_time=signing_time or attrdict.get('signing_time'),
                        signature_type=v['/SubFilter'][1:],  # ETSI.CAdES.detached, ...
                        signature_handler=v['/Filter'][1:],
                        raw=raw_signature_data,
                    ))
                    signatures.append(Signature(attrdict))

    return signatures

def main():
    st.set_page_config(page_title="Fiq's Signature Checker", page_icon=':memo:', layout="centered", initial_sidebar_state="auto", menu_items=None)
    st.header("Fiq's Signature Checker :memo:", divider='rainbow')

    # File upload
    uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

    if uploaded_file is not None:
        # Check for signature
        signatures = get_pdf_signatures(uploaded_file)

        if not signatures:
            st.error('No signature detected', icon="🚨")
        else:
            st.success('Signature(s) detected:')
            for index, signature in enumerate(signatures, start=1):
                st.write(f"--- {signature.type} ---")
                st.write(f"Signature: {signature}")
                st.write(f"Signer: {signature.signer_name}")
                st.write(f"Signing time: {signature.signing_time}")
                certificate = signature.certificate

if __name__ == "__main__":
    main()
