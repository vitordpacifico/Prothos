def load_wordlist(path):

    with open(path) as f:
        return [x.strip() for x in f if x.strip()]