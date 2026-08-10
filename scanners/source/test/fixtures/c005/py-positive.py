import os


def read_upload(request):
    return open('/data/uploads/' + request.args.get('name'), 'r')


def read_upload_joined(base_dir, params):
    return open(os.path.join(base_dir, params['name']), 'r')
